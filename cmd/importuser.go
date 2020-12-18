/*
 * Copyright 2020-2020 The NATS Authors
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
	"io/ioutil"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createImportUserCmd() *cobra.Command {
	var params ImportUser
	cmd := &cobra.Command{
		Use:          "user --file <user-jwt/user-creds>",
		Short:        "Imports an user from a jwt or user and nkey from a creds file",
		Example:      `nsc import user --file <account-jwt>`,
		Args:         MaxArgs(0),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.skip, "skip", "", false, "skip validation issues")
	cmd.Flags().BoolVarP(&params.overwrite, "overwrite", "", false, "overwrite existing user")
	cmd.Flags().StringVarP(&params.file, "file", "f", "", "user jwt or creds to import")
	return cmd
}

func init() {
	importCmd.AddCommand(createImportUserCmd())
}

type ImportUser struct {
	fileImport
}

func (p *ImportUser) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *ImportUser) Validate(ctx ActionCtx) error {
	return p.fileImport.Validate(ctx, ".jwt", ".creds")
}

// returns true when blocking and not skipped
func validateAndReport(claim jwt.Claims, force bool, r *store.Report) bool {
	vr := jwt.ValidationResults{}
	claim.Validate(&vr)
	for _, i := range vr.Issues {
		if i.Blocking {
			r.AddError("validation resulted in: %s", i.Description)
		} else {
			r.AddWarning("validation resulted in: %s", i.Description)
		}
	}
	if vr.IsBlocking(true) && !force {
		r.AddError("validation is blocking, skip with --skip")
		return true
	}
	return false
}

func (p *ImportUser) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	content, err := ioutil.ReadFile(p.file)
	if err != nil {
		r.AddError("failed to import %#q: %v", p.file, err)
		return r, err
	}
	theJWT := ""
	var kp nkeys.KeyPair
	if strings.HasSuffix(p.file, ".jwt") {
		theJWT = string(content)
	} else {
		if theJWT, err = jwt.ParseDecoratedJWT(content); err == nil {
			if kp, err = jwt.ParseDecoratedUserNKey(content); err != nil {
				r.AddError("failed to parse decorated key in %#q: %v", p.file, err)
				return r, err
			}
		}
	}
	claim, err := jwt.DecodeUserClaims(theJWT)
	if err != nil {
		r.AddError("failed to decode %#q: %v", p.file, err)
		return r, err
	}
	if validateAndReport(claim, p.skip, r) {
		return r, err
	}
	acc := claim.IssuerAccount
	if acc == "" {
		acc = claim.Issuer
	}
	var accClaim *jwt.AccountClaims
	accs, _ := ctx.StoreCtx().Store.ListSubContainers(store.Accounts)
	for _, accName := range accs {
		accClaim, _ = ctx.StoreCtx().Store.ReadAccountClaim(accName)
		if accClaim.Subject != acc {
			accClaim = nil
		} else {
			break
		}
	}
	if accClaim == nil {
		r.AddError("referenced Account %s not found, import first", acc)
		return r, nil
	}
	if ctx.StoreCtx().Store.Has(store.Accounts, accClaim.Name, store.Users, store.JwtName(claim.Name)) {
		if !p.overwrite {
			r.AddError("user already exists, overwrite with --overwrite")
			return r, nil
		}
		if old, err := ctx.StoreCtx().Store.ReadUserClaim(accClaim.Name, claim.Name); err != nil {
			r.AddError("existing User not found: %v", err)
			return r, nil
		} else if old.Subject != claim.Subject {
			r.AddError("existing User has a name collision only and does not reference the same entity "+
				"(Subject is %s and differs from %s). This problem needs to be resolved manually.",
				old.Subject, claim.Subject)
			return r, nil
		}
	}
	sameAccount := false
	keys := []string{accClaim.Subject}
	keys = append(keys, accClaim.SigningKeys.Keys()...)
	for _, key := range keys {
		if key == claim.Issuer {
			sameAccount = true
			break
		}
	}
	if !sameAccount {
		r.AddError("can only import user signed by exiting account. Possibly update your account")
		return r, nil
	}
	if kp != nil {
		keyPath, err := ctx.StoreCtx().KeyStore.Store(kp)
		if err != nil {
			r.AddError("key could not be stored: %v", err)
			return r, nil
		}
		r.AddOK("key stored %s", keyPath)
	}
	sub, err := ctx.StoreCtx().Store.StoreClaim([]byte(theJWT))
	if err != nil {
		r.AddError("Error when storing user: %v", err)
	}
	r.Add(sub)
	if r.HasNoErrors() {
		r.AddOK("user %s was successfully imported", claim.Name)
	} else {
		r.AddOK("user %s was not imported: %v", claim.Name, err)
	}
	return r, nil
}
