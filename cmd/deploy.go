/*
 * Copyright 2018-2019 The NATS Authors
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
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDeployCmd() *cobra.Command {
	var allAccounts bool
	var params DeployCmdParams
	var cmd = &cobra.Command{
		Short: "Deploy an account to a remote/managed operator",
		Long: `Deploy pushes an account JWT to a remote operator, such as a managed service like NGS. 
Deployed accounts are copied to the deployed operator, but are not to be edited. 
All edits should happen on a local operator, and then deployed as necessary. The
copy under the operator may be slightly different from your original account, as
operators can set limits depending on your service plan.`,
		Example: "deploy",
		Use: `deploy --url  <operator_url>
deploy --operator <operator name>`,
		Args: MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			var accounts []DeployCmdParams
			if allAccounts {
				tc := GetConfig()
				if tc.Operator == "" {
					return errors.New("create or add an operator first")
				}
				s, err := tc.LoadStore(tc.Operator)
				if err != nil {
					return err
				}
				names, err := s.ListSubContainers(store.Accounts)
				if err != nil {
					return err
				}
				for _, n := range names {
					var dp DeployCmdParams
					dp.operator = params.operator
					dp.url = params.url
					dp.AccountContextParams.Name = n
					accounts = append(accounts, dp)
				}
			} else {
				accounts = append(accounts, params)
			}
			for _, dp := range accounts {
				if err := RunAction(cmd, args, &dp); err != nil {
					return fmt.Errorf("deploy %q failed - %v", dp.AccountContextParams.Name, err)
				}
				cmd.Printf("deployed %q to operator %q\n", dp.AccountContextParams.Name, dp.claim.Name)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&allAccounts, "all-accounts", "A", false, "deploy all accounts under the current operator")
	cmd.Flags().StringVarP(&params.operator, "operator", "o", "", "operator to deploy to")
	cmd.Flags().StringVarP(&params.url, "url", "u", "", "operator url to deploy to")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createDeployCmd())
}

type DeployCmdParams struct {
	AccountContextParams
	signer        SignerParams
	operator      string
	operatorToken string
	claim         *jwt.OperatorClaims
	url           string
	asu           string
}

func (p *DeployCmdParams) SetDefaults(ctx ActionCtx) error {
	if p.url != "" && p.operator != "" {
		return errors.New("specify only one of url or operator")
	}
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.signer.SetDefaults(nkeys.PrefixByteAccount, false, ctx)

	return nil
}

func (p *DeployCmdParams) PreInteractive(ctx ActionCtx) error {
	if err := p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	conf := GetConfig()
	operators := conf.ListOperators()
	var choices []string
	for _, v := range operators {
		if v != conf.Operator {
			choices = append(choices, v)
		}
	}
	choices = append(choices, "other")
	sel, err := cli.PromptChoices("select operator to deploy to", "", choices)
	if err != nil {
		return err
	}
	if sel == len(choices)-1 {
		p.url, err = cli.Prompt("enter operator url", "", true, cli.URLValidator("http", "https"))
		if err != nil {
			return err
		}
	} else {
		p.operator = choices[sel]
	}

	return p.signer.Edit(ctx)
}

func (p *DeployCmdParams) Load(ctx ActionCtx) error {
	if p.operator != "" {
		// if we have an operator we try to load the account server from JWT
		os, err := GetConfig().LoadStore(p.operator)
		if err != nil {
			return err
		}
		p.claim, err = os.ReadOperatorClaim()
		if err != nil {
			return err
		}
	} else {
		// otherwise - we need to fetch the URL provided to yield an operator JWT
		data, err := LoadFromURL(p.url)
		if err != nil {
			return fmt.Errorf("error loading from %q: %v", p.url, err)
		}
		p.operatorToken, err = jwt.ParseDecoratedJWT(data)
		if err != nil {
			return fmt.Errorf("error parsing JWT: %v", err)
		}
		p.claim, err = jwt.DecodeOperatorClaims(p.operatorToken)
		if err != nil {
			return fmt.Errorf("error decoding JWT: %v", err)
		}
	}
	if p.claim == nil {
		return errors.New("unable to resolve an operator JWT")
	}
	p.asu = p.claim.AccountServerURL
	return nil
}

func (p *DeployCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DeployCmdParams) Validate(ctx ActionCtx) error {
	if p.operator == "" && p.url == "" {
		return errors.New("an operator name or url is required")
	}
	if p.asu == "" {
		return errors.New("the operator doesn't have an account server url")
	}
	if err := p.signer.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeployCmdParams) Run(ctx ActionCtx) error {
	var err error
	var managedStore *store.Store
	if p.operatorToken != "" {
		s, err := GetConfig().LoadStore(p.claim.Name)
		if err == nil {
			// update it
			managedStore = s
			if err := s.StoreClaim([]byte(p.operatorToken)); err != nil {
				return fmt.Errorf("error updating operator jwt: %v", err)
			}
		} else {
			// create it
			onk := &store.NamedKey{Name: p.claim.Name}
			os, err := store.CreateStore(p.claim.Name, GetConfig().StoreRoot, onk)
			if err != nil {
				return err
			}
			if err = os.StoreClaim([]byte(p.operatorToken)); err != nil {
				return err
			}
			managedStore = os
		}
	} else {
		managedStore, err = GetConfig().LoadStore(p.operator)
		if err != nil {
			return err
		}
	}
	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	u, err := url.Parse(p.asu)
	if err != nil {
		return err
	}
	u.Path = path.Join(u.Path, "accounts", ac.Subject)

	raw, err := ac.Encode(p.signer.signerKP)
	if err != nil {
		return err
	}

	d, err := PushAccount(u.String(), []byte(raw))
	if err != nil {
		return fmt.Errorf("error pushing to %q: %v", u.String(), err)
	}

	if d != nil {
		d = append(d, '\n')
		Write("--", d)

		// ask for the JWT
		r, err := http.Get(u.String())
		if err != nil {
			return fmt.Errorf("error retrieving jwt from %q: %v", u.String(), err)
		}
		defer r.Body.Close()
		m, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("error reading server response: %v", err)
		}
		s, err := jwt.ParseDecoratedJWT(m)
		if err != nil {
			return fmt.Errorf("error parsing JWT returned by the server: %v", err)
		}
		aac, err := jwt.DecodeAccountClaims(s)
		if err != nil {
			return fmt.Errorf("error decoding JWT returned by the server: %v", err)
		}
		if err := managedStore.StoreClaim([]byte(s)); err != nil {
			return fmt.Errorf("error storing JWT returned by the server: %v", err)
		}
		ad := NewAccountDescriber(*aac)
		Write("--", []byte(ad.Describe()))
	}
	return nil
}
