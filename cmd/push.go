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
	"net/url"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createPushCmd() *cobra.Command {
	var params PushCmdParams
	var cmd = &cobra.Command{
		Short:   "Push an account jwt to an Account JWT Server",
		Example: "push",
		Use: `push (currentAccount)
push -a <accountName>
push -A (all accounts)`,
		Args: MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().BoolVarP(&params.allAccounts, "all", "A", false, "push all accounts under the current operator (exclusive of -a)")
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "push regardless of validation issues")
	cmd.Flags().StringVarP(&params.ASU, "account-jwt-server-url", "u", "", "set account jwt server url for nsc sync (only http/https urls supported if updating with nsc)")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createPushCmd())
}

type PushCmdParams struct {
	AccountContextParams
	ASU         string
	allAccounts bool
	force       bool
	targeted    []string
}

func (p *PushCmdParams) SetDefaults(ctx ActionCtx) error {
	if p.allAccounts && p.Name != "" {
		return errors.New("specify only one of --account or --all-accounts")
	}

	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	if p.ASU == "" {
		op, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		p.ASU = op.AccountServerURL
	}
	c := GetConfig()
	accounts, err := c.ListAccounts()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return fmt.Errorf("operator %q has no accounts", c.Operator)
	}
	if !p.allAccounts {
		found := false
		for _, v := range accounts {
			if v == p.Name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("account %q is not under operator %q - nsc env to check your env", p.Name, c.Operator)
		}
	}
	return nil
}

func (p *PushCmdParams) validURL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("url cannot be empty")
	}

	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	supported := []string{"http", "https"}

	ok := false
	for _, v := range supported {
		if scheme == v {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("scheme %q is not supported (%v)", scheme, strings.Join(supported, ", "))
	}
	return nil
}

func (p *PushCmdParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if !p.allAccounts {
		if err = p.AccountContextParams.Edit(ctx); err != nil {
			return err
		}
	}
	p.ASU, err = cli.Prompt("Account Server URL", p.ASU, cli.Val(p.validURL))
	return err
}

func (p *PushCmdParams) Load(ctx ActionCtx) error {
	if !p.allAccounts {
		if err := p.AccountContextParams.Validate(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *PushCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *PushCmdParams) Validate(ctx ActionCtx) error {
	if p.ASU == "" {
		return errors.New("no account server url was provided by the operator jwt")
	}

	if err := p.validURL(p.ASU); err != nil {
		return err
	}

	if !p.force {
		oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}

		// validate the jwts don't have issues
		accounts, err := p.getSelectedAccounts()
		if err != nil {
			return err
		}

		for _, v := range accounts {
			raw, err := ctx.StoreCtx().Store.Read(store.Accounts, v, store.JwtName(v))
			if err != nil {
				return err
			}

			ac, err := jwt.DecodeAccountClaims(string(raw))
			if err != nil {
				return fmt.Errorf("unable to push account %q: %v", v, err)
			}
			var vr jwt.ValidationResults
			ac.Validate(&vr)
			for _, e := range vr.Issues {
				if e.Blocking || e.TimeCheck {
					return fmt.Errorf("unable to push account %q as it has validation issues: %v", v, e.Description)
				}
			}
			if !ctx.StoreCtx().Store.IsManaged() && !oc.DidSign(ac) {
				return fmt.Errorf("unable to push account %q as it is not signed by the operator %q", v, ctx.StoreCtx().Operator.Name)
			}
		}
	}

	return nil
}

func (p *PushCmdParams) getSelectedAccounts() ([]string, error) {
	if p.allAccounts {
		a, err := GetConfig().ListAccounts()
		if err != nil {
			return nil, err
		}
		return a, nil
	} else {
		return []string{p.AccountContextParams.Name}, nil
	}
}

func (p *PushCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	var err error
	p.targeted, err = p.getSelectedAccounts()
	if err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(true)
	for _, v := range p.targeted {
		sub := store.NewReport(store.OK, "push %s to account server", v)
		sub.Opt = store.DetailsOnErrorOrWarning
		r.Add(sub)
		ps, err := p.pushAccount(v, ctx)
		if ps != nil {
			sub.Add(store.HoistChildren(ps)...)
		}
		if err != nil {
			sub.AddError("failed to push account %q: %v", v, err)
		}
		if sub.OK() {
			sub.Label = fmt.Sprintf("pushed %q to account server", v)
		}
	}

	return r, nil
}

func (p *PushCmdParams) pushAccount(n string, ctx ActionCtx) (store.Status, error) {
	raw, err := ctx.StoreCtx().Store.Read(store.Accounts, n, store.JwtName(n))
	if err != nil {
		return nil, err
	}
	c, err := jwt.DecodeAccountClaims(string(raw))
	if err != nil {
		return nil, err
	}
	u, err := AccountJwtURLFromString(p.ASU, c.Subject)
	if err != nil {
		return nil, err
	}
	return store.PushAccount(u, raw)
}
