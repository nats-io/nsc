/*
 * Copyright 2018-2021 The NATS Authors
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

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createEditSkopedSkCmd() *cobra.Command {
	var params EditScopedSkParams
	cmd := &cobra.Command{
		Use:   "signing-key",
		Short: "Edit a scoped signing key or promote a signing key to be scoped",
		Long: `# Edit permissions associated with the account (n) signing key (sk):
nsc edit signing-key --account <n> --sk <sk> --allow-pubsub <subject>,...
nsc edit signing-key --account <n> --sk <sk> --allow-pub <subject>,...
nsc edit signing-key --account <n> --sk <sk> --allow-sub <subject>,...
`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.role, "role", "", "", "role associated with the signing key scope")
	cmd.Flags().StringVarP(&params.description, "description", "", "", "user description associated with the role")
	params.sk.BindFlagsForOne("sk", "", nkeys.PrefixByteAccount, cmd)
	params.AccountContextParams.BindFlags(cmd)
	params.UserPermissionLimits.BindFlags(cmd)
	return cmd
}

func init() {
	editCmd.AddCommand(createEditSkopedSkCmd())
}

type EditScopedSkParams struct {
	sk          SigningKeysParams
	skName      string
	role        string
	description string
	claim       *jwt.AccountClaims
	UserPermissionLimits
	AccountContextParams
	SignerParams
}

func (p *EditScopedSkParams) SetDefaults(ctx ActionCtx) error {
	p.skName = NameFlagOrArgument(p.skName, ctx)
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	return nil
}

func (p *EditScopedSkParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *EditScopedSkParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if p.sk.Empty() && p.role != "" {
		kp := keyByRoleName(ctx.StoreCtx().KeyStore, p.claim, p.role)
		if kp != nil {
			s, err := kp.PublicKey()
			if err != nil {
				return err
			}
			p.sk.paths = append(p.sk.paths, s)
		}
	}

	// try to normalize the values
	if err := p.sk.Valid(); err != nil {
		// if we are not valid, that means we didn't get a sk or "generate"
		if len(p.sk.paths) > 0 {
			// try that as a scope role
			kp := keyByRoleName(ctx.StoreCtx().KeyStore, p.claim, p.sk.paths[0])
			if kp != nil {
				s, err := kp.PublicKey()
				if err != nil {
					return err
				}
				p.skName = s
			}
		}
	}

	if p.skName == "" {
		pks, err := p.sk.PublicKeys()
		if err != nil {
			return err
		}
		if len(pks) > 0 {
			p.skName = pks[0]
		} else {
			ctx.CurrentCmd().SilenceUsage = false
			return fmt.Errorf("signing key is required")
		}
	}

	s, found := p.claim.SigningKeys.GetScope(p.skName)
	if !found {
		kp := keyByRoleName(ctx.StoreCtx().KeyStore, p.claim, p.skName)
		if kp == nil {
			// Couldn't find key by role name.
			// Try resolving seed, public key, or filepath.
			kp, err = store.ResolveKey(p.skName)
			if err != nil {
				return err
			}
		}
		if kp == nil {
			// Still don't have a key pair, give up.
			return fmt.Errorf("signing-key not found")
		}

		p.skName, err = kp.PublicKey()
		if err != nil {
			return fmt.Errorf("signing-key public key error: %s", err)
		}
	}
	if s == nil {
		s = &jwt.UserScope{}
	}
	return p.UserPermissionLimits.Load(ctx, s.(*jwt.UserScope).Template)
}

func (p *EditScopedSkParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *EditScopedSkParams) Validate(ctx ActionCtx) error {
	p.UserPermissionLimits.Validate(ctx)

	if err := p.SignerParams.ResolveWithPriority(ctx, p.claim.Issuer); err != nil {
		return err
	}

	return nil
}

func (p *EditScopedSkParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	r.ReportSum = false
	scope, _ := p.claim.SigningKeys.GetScope(p.skName)
	if scope == nil {
		scope = jwt.NewUserScope()
		scope.(*jwt.UserScope).Key = p.skName
	}
	if ctx.AnySet("role") {
		scope.(*jwt.UserScope).Role = p.role
	}
	if ctx.AnySet("description") {
		scope.(*jwt.UserScope).Description = p.description
	}
	s, err := p.UserPermissionLimits.Run(ctx, &(scope.(*jwt.UserScope).Template))
	if err != nil {
		return nil, err
	}
	if s != nil {
		r.Add(s.Details...)
	}
	p.claim.SigningKeys.AddScopedSigner(scope)

	// we sign
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	// if the signer is not allowed, the store will reject
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(token))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
	}
	if r.HasNoErrors() {
		r.AddOK("edited signing key %q", p.skName)
	}
	return r, nil
}
