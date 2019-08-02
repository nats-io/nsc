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
	"fmt"
	"path/filepath"

	"github.com/nats-io/nsc/cli"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createInitCmd() *cobra.Command {
	var params EasyCmdParams
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create an operator, account and user",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			// validation function for provided name
			checkName := func(v string) error {
				operators := GetConfig().ListOperators()
				for _, o := range operators {
					if o == v {
						return fmt.Errorf("an operator named %q already exists", v)
					}
				}
				return nil
			}

			// if they didn't provide any values, prompt - this is first contact
			prompted := false
			if !cmd.Flag("name").Changed && !cmd.Flag("url").Changed {
				prompted = true
				params.Name, err = cli.Prompt("name your operator, account and user", params.Name, true, checkName)
				if err != nil {
					return err
				}
			}
			if err := checkName(params.Name); err != nil {
				return err
			}
			// possibly no stores exist yet - create one
			if err := params.createStore(); err != nil {
				return err
			}
			if err := RunAction(cmd, args, &params); err != nil {
				return fmt.Errorf("init failed: %v", err)
			}
			cmd.Printf("Success!! created a new operator, account and user named %q.\n", params.Name)
			cmd.Printf("User creds file stored in %q\n\n", params.User.CredsPath)

			if prompted {
				ok, err := cli.PromptBoolean("deploy account to a managed operator", false)
				if ok {
					params.Deploy, err = cli.Prompt("enter operator url", "", true, cli.URLValidator("http", "https"))
					if err != nil {
						return err
					}
				}
			}

			if params.Deploy != "" {
				var deploy DeployCmdParams
				deploy.AccountContextParams.Name = params.Name
				deploy.url = params.Deploy

				if err := RunAction(cmd, args, &deploy); err != nil {
					return fmt.Errorf("deploy %q failed - %v", params.Name, err)
				}
				cmd.Printf("Success!! deployed %q to operator %q\n", params.Name, deploy.claim.Name)
			}

			if params.Deploy == "" {
				cmd.Printf("\n\nTo run a local server using this configuration, enter:\n")
				cmd.Printf("> nsc generate config --mem-resolver --config-file <path/server.conf>\n")
				cmd.Printf("start a nats-server using the generated config:\n")
				cmd.Printf("> nats-server -c <path/server.conf>\n\n")

				cmd.Printf("Or deploy your account to a managed service enter:\n")
				cmd.Printf("> nsc deploy --url https://jwt.ngs.local:6060/jwt/v1/operator\n\n")
			}

			cmd.Printf("To listen for messages enter:\n")
			cmd.Printf("> nsc tools sub \">\"\n")
			cmd.Printf("To publish your first messages enter:\n")
			cmd.Printf("> nsc tools pub hello \"Hello World\"\n\n")

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.Name, "name", "n", "Test", "name used for the operator, account and user")
	cmd.Flags().StringVarP(&params.Deploy, "url", "u", "", "managed operator deploy url")
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createInitCmd())
}

type EasyCmdParams struct {
	Name      string
	Operator  keys
	Account   keys
	User      keys
	Deploy    string
	DeployURL string
}

type keys struct {
	KP        nkeys.KeyPair
	PubKey    string
	KeyPath   string
	CredsPath string
}

func (p *EasyCmdParams) SetDefaults(ctx ActionCtx) error {
	return nil
}
func (p *EasyCmdParams) PreInteractive(ctx ActionCtx) error {
	return nil
}
func (p *EasyCmdParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *EasyCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *EasyCmdParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *EasyCmdParams) createStore() error {
	root, err := filepath.Abs(GetConfig().StoreRoot)
	if err != nil {
		return err
	}
	p.Operator.KP, err = nkeys.CreateOperator()
	if err != nil {
		return err
	}
	nk := &store.NamedKey{Name: p.Name, KP: p.Operator.KP}
	_, err = store.CreateStore(p.Name, root, nk)
	if err != nil {
		return err
	}
	GetConfig().Operator = p.Name
	if err := GetConfig().Save(); err != nil {
		return err
	}
	return nil
}

func (p *EasyCmdParams) setOperatorDefaults(ctx ActionCtx) error {
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	oc.OperatorServiceURLs.Add("nats://localhost:4222")
	token, err := oc.Encode(p.Operator.KP)
	if err != nil {
		return err
	}
	if err := ctx.StoreCtx().Store.StoreClaim([]byte(token)); err != nil {
		return err
	}

	p.Operator.KeyPath, err = ctx.StoreCtx().KeyStore.Store(p.Operator.KP)
	if err != nil {
		return err
	}
	return nil
}

func (p *EasyCmdParams) createAccount(ctx ActionCtx) error {
	var err error
	p.Account.KP, err = nkeys.CreateAccount()
	if err != nil {
		return err
	}
	p.Account.PubKey, err = p.Account.KP.PublicKey()
	ac := jwt.NewAccountClaims(p.Account.PubKey)
	ac.Name = p.Name
	at, err := ac.Encode(p.Operator.KP)
	if err != nil {
		return err
	}
	if err := ctx.StoreCtx().Store.StoreClaim([]byte(at)); err != nil {
		return err
	}
	p.Account.KeyPath, err = ctx.StoreCtx().KeyStore.Store(p.Account.KP)
	if err != nil {
		return err
	}
	return nil
}

func (p *EasyCmdParams) createUser(ctx ActionCtx) error {
	var err error
	p.User.KP, err = nkeys.CreateUser()
	if err != nil {
		return err
	}
	p.User.PubKey, err = p.User.KP.PublicKey()
	if err != nil {
		return err
	}

	uc := jwt.NewUserClaims(p.User.PubKey)
	uc.Name = p.Name
	at, err := uc.Encode(p.Account.KP)
	if err != nil {
		return err
	}
	if err := ctx.StoreCtx().Store.StoreClaim([]byte(at)); err != nil {
		return err
	}
	p.User.KeyPath, err = ctx.StoreCtx().KeyStore.Store(p.User.KP)
	if err != nil {
		return err
	}
	config, err := GenerateConfig(ctx.StoreCtx().Store, p.Name, p.Name, p.User.KP)
	p.User.CredsPath, err = ctx.StoreCtx().KeyStore.MaybeStoreUserCreds(p.Name, p.Name, config)
	if err != nil {
		return err
	}
	return nil
}

func (p *EasyCmdParams) Run(ctx ActionCtx) error {
	if err := p.setOperatorDefaults(ctx); err != nil {
		return err
	}
	if err := p.createAccount(ctx); err != nil {
		return err
	}
	if err := p.createUser(ctx); err != nil {
		return err
	}

	return nil
}
