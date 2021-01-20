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
	"fmt"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createReIssueOperatorCmd() *cobra.Command {
	var params reIssueOperator
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Re-issues the operator with a new identity and re-signs affected accounts",
		Example:      `nsc reissue operator`,
		Args:         MaxArgs(0),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.turnIntoSigningKey, "convert-to-signing-key", "", false,
		"turn operator identity key into signing key (avoids account re-signing)")
	return cmd
}

// removeCmd represents the resign command
var reIssue = &cobra.Command{
	Use:   "reissue",
	Short: "Re-issue objects with a new identity key",
}

func init() {
	reIssue.AddCommand(createReIssueOperatorCmd())
	GetRootCmd().AddCommand(reIssue)
}

type reIssueOperator struct {
	turnIntoSigningKey bool
}

func (p *reIssueOperator) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *reIssueOperator) Load(ctx ActionCtx) error {
	return nil
}

func (p *reIssueOperator) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *reIssueOperator) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *reIssueOperator) Validate(ctx ActionCtx) error {
	if ctx.StoreCtx().Store.IsManaged() {
		return fmt.Errorf("resign is only supported in non managed stores")
	}
	if _, err := ctx.StoreCtx().Store.ReadOperatorClaim(); err != nil {
		return err
	}
	return nil
}

func (p *reIssueOperator) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	op, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		r.AddError("failed to obtain operator: %v", err)
		return r, err
	}
	opKp, err := nkeys.CreateOperator()
	if err != nil {
		r.AddError("failed to generate new operator identity: %v", err)
		return r, err
	}
	if _, err := ctx.StoreCtx().KeyStore.Store(opKp); err != nil {
		r.AddError("failed to store new operator identity: %v", err)
		return r, err
	}
	opPub, err := opKp.PublicKey()
	if err != nil {
		r.AddError("failed to obtain public key from new identity: %v", err)
		return r, err
	}
	oldPubKey := op.Subject
	if p.turnIntoSigningKey {
		op.SigningKeys.Add(oldPubKey)
	}
	op.Subject = opPub
	if opJWT, err := op.Encode(opKp); err != nil {
		r.AddError("failed to encode new operator jwt: %v", err)
		return r, err
	} else if err := ctx.StoreCtx().Store.StoreRaw([]byte(opJWT)); err != nil {
		r.AddError("failed to store new operator jwt: %v", err)
		return r, err
	}
	r.AddOK("operator %q successfully changed identity to: %s", op.Name, opPub)
	if p.turnIntoSigningKey {
		r.AddOK("old operator key %q turned into signing key", opPub)
		return r, nil
	}
	accounts, err := ctx.StoreCtx().Store.ListSubContainers(store.Accounts)
	if err != nil {
		r.AddError("failed to obtain accounts: %v", err)
	}
	for _, acName := range accounts {
		claim, err := ctx.StoreCtx().Store.ReadAccountClaim(acName)
		if err != nil {
			r.AddError("failed reading account %s: %v", acName, err)
		}
		if claim.Issuer != oldPubKey {
			r.AddOK("account %q already signed properly", acName)
			continue
		}
		if accJWT, err := claim.Encode(opKp); err != nil {
			r.AddError("account %q error during encoding: %v", acName, err)
		} else if err := ctx.StoreCtx().Store.StoreRaw([]byte(accJWT)); err != nil {
			r.AddError("failed to store new account jwt for account %q: %v", acName, err)
		}
		r.AddOK("account %q re-signed", acName)
	}
	return r, nil
}
