// Copyright 2020-2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createReIssueOperatorCmd() *cobra.Command {
	var params reIssueOperator
	cmd := &cobra.Command{
		Use: "operator",
		Short: "Re-issues the operator with a new identity and re-signs affected accounts.\n" +
			"\tWhen `--private-key` flag is provided with an operator seed, the identity\n" +
			"\tspecified will be used for the operator and as the issuer for the accounts.\n" +
			"\tNote use of this command could create a disruption. Please backup your server\n" +
			"\tand nsc environment prior to use.",
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
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	return cmd
}

// removeCmd represents the resign command
var reIssue = &cobra.Command{
	Use:   "reissue",
	Short: "Re-issue objects with a new identity key",
}

func init() {
	GetRootCmd().AddCommand(reIssue)
	reIssue.AddCommand(createReIssueOperatorCmd())
	reIssue.AddCommand(createReissueAccountCmd())
}

type reIssueOperator struct {
	turnIntoSigningKey bool
	name               string
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
	store := ctx.StoreCtx().Store
	if p.name != "" {
		var err error
		store, err = GetStoreForOperator(p.name)
		if err != nil {
			return err
		}
	}
	if store.IsManaged() {
		return fmt.Errorf("resign is only supported in non managed stores")
	}
	if op, err := store.ReadOperatorClaim(); err != nil {
		return err
	} else if op.StrictSigningKeyUsage && !p.turnIntoSigningKey && len(op.SigningKeys) == 0 {
		return fmt.Errorf("resign of strict operator is only supported with signing keys present")
	}
	return nil
}

func (p *reIssueOperator) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	r := store.NewDetailedReport(true)
	s := ctx.StoreCtx().Store
	if p.name != "" {
		if s, err = GetStoreForOperator(p.name); err != nil {
			r.AddError("failed to load operator %s: %v", p.name, err)
			return r, err
		}
	}
	op, err := s.ReadOperatorClaim()
	if err != nil {
		r.AddError("failed to obtain operator: %v", err)
		return r, err
	}
	opKp, err := nkeys.CreateOperator()
	if err != nil {
		r.AddError("failed to generate new operator identity: %v", err)
		return r, err
	}
	if KeyPathFlag != "" {
		if strings.HasPrefix(KeyPathFlag, "O") {
			KeyPathFlag, err = ctx.StoreCtx().KeyStore.GetSeed(KeyPathFlag)
			if err != nil {
				r.AddError("failed to find operator key: %v", err)
				return r, err
			}
		}
		if strings.HasPrefix(KeyPathFlag, "SO") {
			opKp, err = nkeys.FromSeed([]byte(KeyPathFlag))
			if err != nil {
				r.AddError("failed to load operator key from seed: %v", err)
				return r, err
			}
		}
	}
	accountSigningKey := opKp
	if op.StrictSigningKeyUsage && !p.turnIntoSigningKey {
		sp := SignerParams{kind: []nkeys.PrefixByte{nkeys.PrefixByteOperator}}
		err = sp.Resolve(ctx)
		if err != nil || sp.signerKP == nil {
			r.AddError("failed to obtain signing key: %v", err)
			return r, err
		}
		accountSigningKey = sp.signerKP
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
	} else if err := s.StoreRaw([]byte(opJWT)); err != nil {
		r.AddError("failed to store new operator jwt: %v", err)
		return r, err
	}
	r.AddOK("operator %q successfully changed identity to: %s", op.Name, opPub)
	if p.turnIntoSigningKey {
		r.AddOK("old operator key %q turned into signing key", oldPubKey)
		return r, nil
	}
	accounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		r.AddError("failed to obtain accounts: %v", err)
	}
	for _, acName := range accounts {
		claim, err := s.ReadAccountClaim(acName)
		if err != nil {
			r.AddError("failed reading account %s: %v", acName, err)
		}
		if claim.Issuer != oldPubKey {
			r.AddOK("account %q already signed properly", acName)
			continue
		}
		if accJWT, err := claim.Encode(accountSigningKey); err != nil {
			r.AddError("account %q error during encoding: %v", acName, err)
		} else if err := s.StoreRaw([]byte(accJWT)); err != nil {
			r.AddError("failed to store new account jwt for account %q: %v", acName, err)
		}
		r.AddOK("account %q re-signed", acName)
	}
	return r, nil
}
