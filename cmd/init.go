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
	"bytes"
	"fmt"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
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

			return nil
		},
	}
	sr := GetConfig().StoreRoot
	if sr == "" {
		conf, _ := LoadOrInit("nats-io/nsc", NscHomeEnv)
		sr = conf.StoreRoot
	}
	cmd.Flags().StringVarP(&params.Dir, "dir", "d", sr, "directory where the operator directory will be created")
	cmd.Flags().StringVarP(&params.Name, "name", "n", "", "name used for the operator, account and user")
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
	SystemAccount       keys
	SystemUser          keys
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

	if p.Name == "" || p.Name == "*" {
		p.Name = GetRandomName(0)
	}

	tc := GetConfig()
	if p.Prompt {
		p.Dir, err = cli.Prompt("enter a configuration directory", tc.StoreRoot, cli.Val(func(v string) error {
			_, err := Expand(v)
			return err
		}))
		if err != nil {
			return err
		}
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
		sel, err := cli.Select("Select an operator", defsel, choices)
		if err != nil {
			return err
		}
		local := len(ops)
		custom := local + 1
		switch sel {
		case local:
			p.CreateOperator = true
		case custom:
			p.OperatorJwtURL, err = cli.Prompt("Operator URL", "", cli.NewURLValidator("http", "https"))
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
		p.Name, err = cli.Prompt(q, p.Name, cli.Val(OperatorNameValidator))
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
	var err error
	accounts, err := GetConfig().ListAccounts()
	if err != nil {
		return err
	}
	for _, a := range accounts {
		if a == p.Name {
			return fmt.Errorf("an account named %q already exists", p.Name)
		}
	}
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
		onk.Name = GetOperatorName(op.Name, p.OperatorJwtURL)
		p.AccountServerURL = op.AccountServerURL

		if p.AccountServerURL == "" {
			return fmt.Errorf("error importing operator %q - it doesn't define an account server url", onk.Name)
		}

		// see if we already have it
		ts, err := GetConfig().LoadStore(onk.Name)
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

func createSystemAccount(s *store.Context, opKp nkeys.KeyPair) (*keys, *keys, error) {
	var acc keys
	var usr keys
	var err error
	// create system account, signed by this operator
	if acc.KP, err = nkeys.CreateAccount(); err != nil {
		return nil, nil, err
	} else if acc.PubKey, err = acc.KP.PublicKey(); err != nil {
		return nil, nil, err
	}
	sysAccClaim := jwt.NewAccountClaims(acc.PubKey)
	sysAccClaim.Name = "SYS"
	if sysAccJwt, err := sysAccClaim.Encode(opKp); err != nil {
		return nil, nil, err
	} else if _, err := s.Store.StoreClaim([]byte(sysAccJwt)); err != nil {
		return nil, nil, err
	} else if acc.KeyPath, err = s.KeyStore.Store(acc.KP); err != nil {
		return nil, nil, err
	}
	// create system account user and creds
	if usr.KP, err = nkeys.CreateUser(); err != nil {
		return nil, nil, err
	} else if usr.PubKey, err = usr.KP.PublicKey(); err != nil {
		return nil, nil, err
	}
	sysUsrClaim := jwt.NewUserClaims(usr.PubKey)
	sysUsrClaim.Name = "sys"
	if sysUsrJwt, err := sysUsrClaim.Encode(acc.KP); err != nil {
		return nil, nil, err
	} else if _, err := s.Store.StoreClaim([]byte(sysUsrJwt)); err != nil {
		return nil, nil, err
	} else if usr.KeyPath, err = s.KeyStore.Store(usr.KP); err != nil {
		return nil, nil, err
	}
	config, err := GenerateConfig(s.Store, sysAccClaim.Name, sysUsrClaim.Name, usr.KP)
	if err != nil {
		return nil, nil, err
	}
	if usr.CredsPath, err = s.KeyStore.MaybeStoreUserCreds(sysAccClaim.Name, sysUsrClaim.Name, config); err != nil {
		return nil, nil, err
	}
	return &acc, &usr, nil
}

func (p *InitCmdParams) setOperatorDefaults(ctx ActionCtx) error {
	ctx.StoreCtx()
	if p.CreateOperator {
		if acc, usr, err := createSystemAccount(ctx.StoreCtx(), p.Operator.KP); err != nil {
			return err
		} else {
			p.SystemAccount = *acc
			p.SystemUser = *usr
		}

		// read/create operator
		oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		oc.OperatorServiceURLs.Add("nats://localhost:4222")
		oc.SystemAccount = p.SystemAccount.PubKey
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
	if err != nil {
		return nil, err
	}
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
	if err != nil {
		return err
	}
	p.User.CredsPath, err = ctx.StoreCtx().KeyStore.MaybeStoreUserCreds(p.Name, p.Name, config)
	if err != nil {
		return err
	}
	return nil
}

func (p *InitCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	r := store.NewDetailedReport(true)
	if p.CreateOperator {
		if err := p.setOperatorDefaults(ctx); err != nil {
			return nil, err
		}
		r.AddOK("created operator %s", p.Name)
		r.AddOK("created system_account: name:SYS id:%s", p.SystemAccount.PubKey)
		r.AddOK("created system account user: name:sys id:%s", p.SystemUser.PubKey)
		r.AddOK("system account user creds file stored in %#q", AbbrevHomePaths(p.SystemUser.CredsPath))
	} else {
		r.AddOK("add managed operator %s", GetConfig().Operator)
	}
	rs, err := p.createAccount(ctx)
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
		return r, err
	}
	r.AddOK("created account %s", p.Name)
	if err := GetConfig().SetAccount(p.Name); err != nil {
		r.AddFromError(err)
		return r, err
	}

	if err := p.createUser(ctx); err != nil {
		r.AddFromError(err)
		return r, err
	}
	r.AddOK("created user %q", p.Name)
	r.AddOK("project jwt files created in %#q", AbbrevHomePaths(p.Dir))
	r.AddOK("user creds file stored in %#q", AbbrevHomePaths(p.User.CredsPath))

	if p.CreateOperator {
		local := `to run a local server using this configuration, enter:
  nsc generate config --mem-resolver --config-file <path/server.conf>
then start a nats-server using the generated config:
  nats-server -c <path/server.conf>`
		r.Add(store.NewServerMessage(local))
	}
	if len(p.ServiceURLs) > 0 {
		var buf bytes.Buffer
		buf.WriteString("operator has service URL(s) set to:\n")
		for _, v := range p.ServiceURLs {
			buf.WriteString(fmt.Sprintf("  %s\n", v))
		}
		buf.WriteRune('\n')
		buf.WriteString("To listen for messages enter:\n")
		buf.WriteString("> nsc tools sub \">\"\n")
		buf.WriteString("\nTo publish your first message enter:\n")
		buf.WriteString("> nsc tools pub hello \"Hello World\"\n")
		r.Add(store.NewServerMessage(buf.String()))
	}
	return r, nil
}
