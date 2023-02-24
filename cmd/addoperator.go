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

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createAddOperatorCmd() *cobra.Command {
	var params AddOperatorParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Add an operator",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunStoreLessAction(cmd, args, &params); err != nil {
				return err
			}
			if NscCwdOnly {
				return nil
			}
			return GetConfig().SetOperator(params.name)
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	cmd.Flags().StringVarP(&params.jwtPath, "url", "u", "", "import from a jwt server url, file, or well known operator")
	cmd.Flags().BoolVarP(&params.genSk, "generate-signing-key", "", false, "generate a signing key with the operator")
	cmd.Flags().BoolVarP(&params.sysAcc, "sys", "s", false, "generate system account with the operator (if specified will be signed with signing key)")
	cmd.Flags().BoolVarP(&params.force, "force", "", false, "on import, overwrite existing when already present")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddOperatorCmd())
}

func JWTUpgradeBannerJWT(ver int) error {
	extra := ""
	if ver == 1 {
		extra = " - please downgrade to 0.5.0 by executing `nsc update --version 0.5.0`."
	}
	return fmt.Errorf(`the operator jwt (v%d) is incompatible this version of nsc%s`,
		ver, extra)
}

type AddOperatorParams struct {
	SignerParams
	TimeParams
	jwtPath  string
	token    string
	name     string
	generate bool
	sysAcc   bool
	force    bool
	genSk    bool
	keyPath  string
}

func (p *AddOperatorParams) SetDefaults(ctx ActionCtx) error {
	p.name = NameFlagOrArgument(p.name, ctx)
	if p.name == "*" {
		p.name = GetRandomName(0)
	}
	p.generate = KeyPathFlag == ""
	p.keyPath = KeyPathFlag
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, false, ctx)

	return nil
}

func (p *AddOperatorParams) PreInteractive(ctx ActionCtx) error {
	var err error

	ok, err := cli.Confirm("import operator from a JWT", true)
	if err != nil {
		return err
	}
	if ok {
		p.sysAcc = false
		p.jwtPath, err = cli.Prompt("path or url for operator jwt", p.jwtPath, cli.Val(func(v string) error {
			// is it is an URL or path
			pv := cli.PathOrURLValidator()
			if perr := pv(v); perr != nil {
				// if it doesn't exist - could it be the name of well known operator
				if os.IsNotExist(perr) {
					wko, _ := FindKnownOperator(v)
					if wko != nil {
						return nil
					}
				}
				return perr
			}
			return nil
		}))
		if err != nil {
			return err
		}
	} else {
		p.name, err = cli.Prompt("operator name", p.name, cli.NewLengthValidator(1))
		if err != nil {
			return err
		}
		if err = p.TimeParams.Edit(); err != nil {
			return err
		}
		if p.sysAcc, err = cli.Confirm("Generate system account?", true); err != nil {
			return err
		}
		if p.genSk, err = cli.Confirm("Generate signing key?", true); err != nil {
			return err
		}
	}

	return nil
}

func (p *AddOperatorParams) Load(ctx ActionCtx) error {
	// change the value of the source to be a well-known
	// operator if that is what they gave us
	if p.jwtPath != "" {
		pv := cli.PathOrURLValidator()
		if err := pv(p.jwtPath); os.IsNotExist(err) {
			ko, _ := FindKnownOperator(p.jwtPath)
			if ko != nil {
				p.jwtPath = ko.AccountServerURL
			}
		}
	}
	if p.jwtPath != "" {
		var err error
		var data []byte
		loadedFromURL := false

		if IsURL(p.jwtPath) {
			loadedFromURL = true
			data, err = LoadFromURL(p.jwtPath)
		} else {
			data, err = Read(p.jwtPath)
		}
		if err != nil {
			return fmt.Errorf("error reading %#q: %v", p.jwtPath, err)
		}

		token, err := jwt.ParseDecoratedJWT(data)
		if err != nil {
			return err
		}
		op, err := jwt.DecodeOperatorClaims(token)
		if err != nil {
			return fmt.Errorf("error importing operator jwt: %v", err)
		}
		if op.Version != 2 {
			return JWTUpgradeBannerJWT(op.Version)
		}
		p.token = token
		if p.name == "" {
			p.name = op.Name
			if loadedFromURL {
				p.name = GetOperatorName(p.name, p.jwtPath)
			}
		}
	}
	return nil
}

func (p *AddOperatorParams) resolveOperatorNKey(s string) (nkeys.KeyPair, error) {
	nk, err := store.ResolveKey(s)
	if err != nil {
		return nil, err
	}
	if nk == nil {
		return nil, fmt.Errorf("a key is required")
	}
	t, err := store.KeyType(nk)
	if err != nil {
		return nil, err
	}
	if t != nkeys.PrefixByteOperator {
		return nil, errors.New("specified key is not a valid operator nkey")
	}
	return nk, nil
}

func (p *AddOperatorParams) validateOperatorNKey(s string) error {
	_, err := p.resolveOperatorNKey(s)
	return err
}

func (p *AddOperatorParams) PostInteractive(ctx ActionCtx) error {
	var err error

	if p.token != "" {
		// nothing to generate
		return nil
	}

	if p.signerKP == nil {
		p.generate, err = cli.Confirm("generate an operator nkey", true)
		if err != nil {
			return err
		}
		if !p.generate {
			p.keyPath, err = cli.Prompt("path to an operator nkey or nkey", p.keyPath, cli.Val(p.validateOperatorNKey))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AddOperatorParams) Validate(ctx ActionCtx) error {
	var err error
	if p.token != "" {
		if p.sysAcc {
			return fmt.Errorf("importing an operator is not compatible with system account generation")
		}
		// validated on load
		return nil
	}
	if p.force {
		return fmt.Errorf("force only works with -u")
	}
	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("operator name is required")
	}

	if err = p.TimeParams.Validate(); err != nil {
		return err
	}

	if p.generate {
		p.signerKP, err = nkeys.CreateOperator()
		if err != nil {
			return err
		}
		if p.keyPath, err = ctx.StoreCtx().KeyStore.Store(p.signerKP); err != nil {
			return err
		}
	} else {
		if p.genSk {
			return fmt.Errorf("signing key can not be added when importing the operator")
		}
	}

	if p.keyPath != "" {
		p.signerKP, err = p.resolveOperatorNKey(p.keyPath)
		if err != nil {
			return err
		}
	}

	if err := p.Resolve(ctx); err != nil {
		return err
	}

	if p.sysAcc && p.signerKP == nil {
		return fmt.Errorf("generating system account requires a key")
	}

	return nil
}

func (p *AddOperatorParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(false)
	operator := &store.NamedKey{Name: p.name, KP: p.signerKP}
	s, err := GetConfig().LoadStore(p.name)
	if s == nil {
		s, err = store.CreateStore(p.name, GetConfig().StoreRoot, operator)
	} else if !p.force {
		err = fmt.Errorf("operator named %s exists already", p.name)
		r.AddError("%v please inspect and use --force to overwrite", err)
	}
	if err != nil {
		return r, err
	}

	var sAcc *keys
	var sUsr *keys
	var skPub string

	if p.token == "" {
		ctx, err := s.GetContext()
		if err != nil {
			return nil, err
		}
		if p.generate {
			p.keyPath, err = ctx.KeyStore.Store(p.signerKP)
			if err != nil {
				return nil, err
			}
		}
		oc, err := ctx.Store.ReadOperatorClaim()
		if err != nil {
			return nil, err
		}
		if p.Start != "" {
			oc.NotBefore, err = p.TimeParams.StartDate()
			if err != nil {
				return nil, err
			}
		}
		if p.Expiry != "" {
			oc.Expires, err = p.TimeParams.ExpiryDate()
			if err != nil {
				return nil, err
			}
		}
		sysAccSigner := p.signerKP
		if p.genSk {
			sysAccSigner, err = nkeys.CreateOperator()
			if err != nil {
				return nil, err
			}
			if _, err := ctx.KeyStore.Store(sysAccSigner); err != nil {
				return nil, err
			}
			skPub, err = sysAccSigner.PublicKey()
			if err != nil {
				return nil, err
			}
			oc.SigningKeys.Add(skPub)
		}
		if p.sysAcc {
			if sAcc, sUsr, err = createSystemAccount(ctx, sysAccSigner); err != nil {
				return nil, err
			}
			oc.SystemAccount = sAcc.PubKey
		}

		p.token, err = oc.Encode(p.signerKP)
		if err != nil {
			return nil, err
		}
	} else {
		ctx, err := s.GetContext()
		if err != nil {
			return nil, err
		}
		oc, err := ctx.Store.ReadOperatorClaim()
		if err == nil {
			ocNew, err := jwt.DecodeOperatorClaims(p.token)
			if err != nil {
				return nil, err
			}
			if ocNew.Version != 2 {
				return nil, JWTUpgradeBannerJWT(ocNew.Version)
			}
			if oc.Subject != ocNew.Subject {
				err := fmt.Errorf("existing and new operator represent different entities")
				if !p.force {
					r.AddError(`%v resolve conflict first or provide "--force" to continue`, err)
					return r, err
				}
				r.AddWarning("%v, forced to continue", err)
			}
		} else if err.(*store.ResourceErr).Err != store.ErrNotExist {
			return nil, err
		}
	}

	if p.generate && p.signerKP != nil {
		pk, _ := p.signerKP.PublicKey()
		r.AddOK("generated and stored operator key %q", pk)
	}
	// not in an action ctx - storing on self-created store
	rs, err := s.StoreClaim([]byte(p.token))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
	}
	if r.HasNoErrors() {
		verb := "added"
		if p.jwtPath != "" {
			verb = "imported"
		}
		r.AddOK("%s operator %q", verb, p.name)
		r.AddOK("When running your own nats-server, make sure they run at least version 2.2.0")
		if sAcc != nil && sUsr != nil {
			if skPub != "" {
				r.AddOK("created operator signing key: %s", skPub)
			}
			r.AddOK("created system_account: name:SYS id:%s", sAcc.PubKey)
			r.AddOK("created system account user: name:sys id:%s", sUsr.PubKey)
			r.AddOK("system account user creds file stored in %#q", AbbrevHomePaths(sUsr.CredsPath))
		}
	}
	return r, err
}
