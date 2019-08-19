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
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createInitCmd() *cobra.Command {
	var params InitCmdParams
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize an environment by creating an operator, account and user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.init(cmd); err != nil {
				return err
			}
			if err := params.resolveOperator(); err != nil {
				return err
			}
			// store doesn't exist yet - make one
			if err := params.createStore(cmd); err != nil {
				return err
			}

			if err := RunAction(cmd, args, &params); err != nil {
				return fmt.Errorf("init failed: %v", err)
			}

			if params.CreateOperator {
				cmd.Printf("Success!! created a new operator, account and user named %q.\n", params.Name)
			} else {
				cmd.Printf("Success!! created an account and user named %q under managed operator %q.\n", params.Name, GetConfig().Operator)
			}
			cmd.Printf("User creds file stored in %q\n", params.User.CredsPath)

			if params.CreateOperator {
				cmd.Printf("\nTo run a local server using this configuration, enter:\n")
				cmd.Printf("> nsc generate config --mem-resolver --config-file <path/server.conf>\n")
				cmd.Printf("start a nats-server using the generated config:\n")
				cmd.Printf("> nats-server -c <path/server.conf>\n")
			}

			if len(params.ServiceURLs) > 0 {
				cmd.Printf("\noperator has service URL(s) set to:\n")
				for _, v := range params.ServiceURLs {
					cmd.Printf("  %s\n", v)
				}
				cmd.Printf("\nTo listen for messages enter:\n")
				cmd.Printf("> nsc tools sub \">\"\n")
				cmd.Printf("\nTo publish your first message enter:\n")
				cmd.Printf("> nsc tools pub hello \"Hello World\"\n\n")
			}

			return nil
		},
	}
	sr := GetConfig().StoreRoot
	if sr == "" {
		conf, _ := LoadOrInit("nats-io/nsc", NscHomeEnv)
		sr = conf.StoreRoot
	}
	cmd.Flags().StringVarP(&params.Dir, "dir", "d", sr, "directory where the operator directory will be created")
	cmd.Flags().StringVarP(&params.Name, "name", "n", "Test", "name used for the operator, account and user")
	cmd.Flags().StringVarP(&params.AccountServerURL, "url", "u", "", "operator account server url")
	cmd.Flags().StringVarP(&params.ManagedOperatorName, "remote-operator", "o", "", "remote well-known operator")
	HoistRootFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createInitCmd())
}

type InitCmdParams struct {
	Prompt              bool
	Dir                 string
	Name                string
	ManagedOperatorName string
	CreateOperator      bool
	Operator            keys
	Account             keys
	User                keys
	OperatorJwtURL      string
	AccountServerURL    string

	PushURL          string
	PushStatus       int
	PushMessage      []byte
	Store            *store.Store
	ServiceURLs      jwt.StringList
	DebugOperatorURL string
}

func (p *InitCmdParams) init(cmd *cobra.Command) error {
	var err error
	// if they didn't provide any values, prompt - this is first contact
	if !cmd.Flag("dir").Changed &&
		!cmd.Flag("name").Changed &&
		!cmd.Flag("url").Changed &&
		!cmd.Flag("remote-operator").Changed {
		p.Prompt = true
	}

	tc := GetConfig()
	if p.Prompt {
		p.Dir, err = cli.Prompt("enter a configuration directory", tc.StoreRoot, true, func(v string) error {
			_, err := Expand(v)
			return err
		})
	}
	p.Dir, err = Expand(p.Dir)
	if err != nil {
		return err
	}

	// user specified a directory that possibly doesn't exist
	if err := MaybeMakeDir(p.Dir); err != nil {
		return err
	}

	// set that directory as the stores root
	if err := tc.ContextConfig.setStoreRoot(p.Dir); err != nil {
		return err
	}
	return tc.Save()
}

func (p *InitCmdParams) resolveOperator() error {
	ops, err := GetWellKnownOperators()
	if err != nil {
		return fmt.Errorf("error reading well-known operators: %v", err)
	}
	if p.Prompt {
		var choices []string
		for _, o := range ops {
			choices = append(choices, o.Name)
		}
		choices = append(choices, "Create Operator", "Other")
		defsel := p.ManagedOperatorName
		if defsel == "" {
			defsel = "Create Operator"
		}
		sel, err := cli.PromptChoices("Select an operator", defsel, choices)
		if err != nil {
			return err
		}
		local := len(ops)
		custom := local + 1
		switch sel {
		case local:
			p.CreateOperator = true
		case custom:
			p.OperatorJwtURL, err = cli.Prompt("Operator URL", "", true, cli.URLValidator("http", "https"))
			if err != nil {
				return err
			}
		default:
			p.OperatorJwtURL = ops[sel].AccountServerURL
		}

		q := "name your account and user"
		if p.CreateOperator {
			q = "name your operator, account and user"
		}
		p.Name, err = cli.Prompt(q, p.Name, true, OperatorNameValidator)
		if err != nil {
			return err
		}
	} else {
		// if they gave mop, resolve it
		if p.AccountServerURL != "" {
			p.OperatorJwtURL = p.AccountServerURL
		} else if p.ManagedOperatorName != "" {
			on := strings.ToLower(p.ManagedOperatorName)
			for _, v := range ops {
				vn := strings.ToLower(v.Name)
				if on == vn {
					p.OperatorJwtURL = v.AccountServerURL
					break
				}
			}
			if p.OperatorJwtURL == "" {
				return fmt.Errorf("error operator %q was not found", p.ManagedOperatorName)
			}
		} else {
			p.CreateOperator = true
		}

	}
	return nil
}

type keys struct {
	KP        nkeys.KeyPair
	PubKey    string
	KeyPath   string
	CredsPath string
}

func (p *InitCmdParams) SetDefaults(ctx ActionCtx) error {
	return nil
}
func (p *InitCmdParams) PreInteractive(ctx ActionCtx) error {
	return nil
}
func (p *InitCmdParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *InitCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *InitCmdParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *InitCmdParams) createStore(cmd *cobra.Command) error {
	cmd.SilenceUsage = true

	var err error
	if err := OperatorNameValidator(p.Name); err != nil {
		return err
	}

	var token string
	var onk store.NamedKey
	onk.Name = p.Name

	if p.CreateOperator {
		p.Operator.KP, err = nkeys.CreateOperator()
		if err != nil {
			return err
		}
		onk.KP = p.Operator.KP
		p.Store, err = store.CreateStore(onk.Name, GetConfig().StoreRoot, &onk)
		if err != nil {
			return err
		}
	} else {
		d, err := LoadFromURL(p.OperatorJwtURL)
		if err != nil {
			return err
		}
		token, err = jwt.ParseDecoratedJWT(d)
		if err != nil {
			return fmt.Errorf("error importing operator jwt: %v", err)
		}
		op, err := jwt.DecodeOperatorClaims(token)
		if err != nil {
			return fmt.Errorf("error decoding operator jwt: %v", err)
		}
		onk.Name = op.Name
		p.AccountServerURL = op.AccountServerURL

		if p.AccountServerURL == "" {
			return fmt.Errorf("error importing operator %q - it doesn't define an account server url", onk.Name)
		}

		// see if we already have it
		ts, err := GetConfig().LoadStore(op.Name)
		if err == nil {
			tso, err := ts.ReadOperatorClaim()
			if err == nil {
				if tso.Subject == op.Subject {
					// we have it
					p.Store = ts
				} else {
					return fmt.Errorf("error a different operator named %q already exists -- specify --dir to create at a different location", onk.Name)
				}
			}
		}
		if p.Store == nil {
			p.Store, err = store.CreateStore(onk.Name, GetConfig().StoreRoot, &onk)
			if err != nil {
				return err
			}
		}
		if err := p.Store.StoreRaw([]byte(token)); err != nil {
			return err
		}
	}

	GetConfig().Operator = onk.Name
	return GetConfig().Save()
}

func (p *InitCmdParams) setOperatorDefaults(ctx ActionCtx) error {
	if p.CreateOperator {
		oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		oc.OperatorServiceURLs.Add("nats://localhost:4222")
		token, err := oc.Encode(p.Operator.KP)
		if err != nil {
			return err
		}
		if p.AccountServerURL != "" {
			oc.AccountServerURL = p.AccountServerURL
		}
		if err := ctx.StoreCtx().Store.StoreRaw([]byte(token)); err != nil {
			return err
		}

		p.Operator.KeyPath, err = ctx.StoreCtx().KeyStore.Store(p.Operator.KP)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *InitCmdParams) createAccount(ctx ActionCtx) (store.Status, error) {
	var err error
	p.Account.KP, err = nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	p.Account.PubKey, err = p.Account.KP.PublicKey()
	ac := jwt.NewAccountClaims(p.Account.PubKey)
	ac.Name = p.Name

	kp := p.Account.KP
	if p.CreateOperator {
		kp = p.Operator.KP
	}
	at, err := ac.Encode(kp)
	if err != nil {
		return nil, err
	}
	p.Account.KeyPath, err = ctx.StoreCtx().KeyStore.Store(p.Account.KP)
	if err != nil {
		return nil, err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(at))
}

func (p *InitCmdParams) createUser(ctx ActionCtx) error {
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
	if err := ctx.StoreCtx().Store.StoreRaw([]byte(at)); err != nil {
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

func (p *InitCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	if p.CreateOperator {
		if err := p.setOperatorDefaults(ctx); err != nil {
			return nil, err
		}
	}
	rs, err := p.createAccount(ctx)
	if err != nil {
		return rs, err
	}
	if err := GetConfig().SetAccount(p.Name); err != nil {
		return rs, err
	}

	if err := p.createUser(ctx); err != nil {
		return rs, err
	}
	return rs, nil
}
