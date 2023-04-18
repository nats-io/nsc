/*
 * Copyright 2018-2023 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createImportAccountCmd() *cobra.Command {
	var params ImportAccount
	cmd := &cobra.Command{
		Use:          "account --file <account-jwt>",
		Short:        "Imports an account from a jwt file and resign with operator if self signed",
		Example:      `nsc import account --file <account-jwt>`,
		Args:         MaxArgs(0),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.skip, "skip", "", false, "skip validation issues, they can be edited out prior to push")
	cmd.Flags().BoolVarP(&params.overwrite, "overwrite", "", false, "overwrite existing account")
	cmd.Flags().StringVarP(&params.file, "file", "j", "", "account jwt to import")
	cmd.Flags().BoolVarP(&params.force, "force", "", false, "import account signed by different operator")
	return cmd
}

func init() {
	importCmd.AddCommand(createImportAccountCmd())
}

type fileImport struct {
	file      string
	skip      bool
	overwrite bool
	force     bool
	content   []byte
}

func (p *fileImport) PreInteractive(ctx ActionCtx) (err error) {
	return nil
}

func (p *fileImport) PostInteractive(ctx ActionCtx) (err error) {
	return nil
}

func (p *fileImport) Load(ctx ActionCtx) (err error) {
	p.content, err = Read(p.file)
	if err != nil {
		return err
	}
	s, err := jwt.ParseDecoratedJWT(p.content)
	if err != nil {
		return err
	}
	p.content = []byte(s)
	return nil
}

func (p *fileImport) Validate(xtx ActionCtx, fileEndings ...string) error {
	fp, err := Expand(p.file)
	if err != nil {
		return err
	}
	fi, err := os.Stat(fp)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%#q is a directory", p.file)
	}
	for _, ending := range fileEndings {
		if strings.HasSuffix(p.file, ending) {
			return nil
		}
	}
	return fmt.Errorf("expected these file endings: %v", fileEndings)
}

type ImportAccount struct {
	SignerParams
	fileImport
}

func (p *ImportAccount) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *ImportAccount) Validate(ctx ActionCtx) error {
	if err := p.fileImport.Validate(ctx, ".jwt"); err != nil {
		return err
	}
	if !ctx.StoreCtx().Store.IsManaged() {
		if err := p.SignerParams.Resolve(ctx); err != nil {
			return err
		}
		signers, err := GetOperatorSigners(ctx)
		if err != nil {
			return err
		}
		ok, err := ValidSigner(p.SignerParams.signerKP, signers)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("invalid account signer")
		}
	}
	return nil
}

func (p *ImportAccount) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	theJWT := p.content
	claim, err := jwt.DecodeAccountClaims(string(theJWT))
	if err != nil {
		r.AddError("failed to decode %#q: %v", p.file, err)
		return r, err
	}
	if validateAndReport(claim, p.skip, r) {
		return r, nil
	}
	if ctx.StoreCtx().Store.HasAccount(claim.Name) {
		if !p.overwrite {
			r.AddError("account already exists, overwrite with --overwrite")
			return r, nil
		}
		if old, err := ctx.StoreCtx().Store.ReadAccountClaim(claim.Name); err != nil {
			r.AddError("existing Account not found: %v", err)
			return r, nil
		} else if old.Subject != claim.Subject {
			r.AddError("existing Account has a name collision only and does not reference the same entity "+
				"(Subject is %s and differs from %s). This problem needs to be resolved manually.",
				old.Subject, claim.Subject)
			return r, nil
		}
	}
	sameOperator := false
	keys, _ := ctx.StoreCtx().GetOperatorKeys()
	for _, key := range keys {
		if key == claim.Issuer {
			sameOperator = true
			break
		}
	}
	if ctx.StoreCtx().Store.IsManaged() {
		if claim.IsSelfSigned() {
			r.AddError("only a non managed store can import a self signed account")
			return r, nil
		}
	} else if claim.IsSelfSigned() || (!sameOperator && p.force) {
		if ajwt, err := claim.Encode(p.signerKP); err != nil {
			r.AddError("error during encoding of self signed account jwt: %v", err)
			return r, nil
		} else {
			theJWT = []byte(ajwt)
			sameOperator = true
		}
	}
	if !sameOperator {
		r.AddError("can only import account signed by same operator. Possibly update your operator")
		return r, nil
	}
	sub, err := ctx.StoreCtx().Store.StoreClaim(theJWT)
	if err != nil {
		r.AddError("error when storing account: %v", err)
	}
	r.Add(sub)
	if r.HasNoErrors() {
		r.AddOK("account %s was successfully imported", claim.Name)
	} else {
		r.AddOK("account %s was not imported: %v", claim.Name, err)
	}
	return r, nil
}
