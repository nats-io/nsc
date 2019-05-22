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
	"sort"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/xlab/tablewriter"

	"github.com/spf13/cobra"
)

func createValidateCommand() *cobra.Command {
	var params ValidateCmdParams
	var cmd = &cobra.Command{
		Short:   "Validate an operator, account(s), and users",
		Example: "validate",
		Use: `validate (current operator/current account/account users)
validate -a <accountName> (current operator/<accountName>/account users)
validate -A (current operator/all accounts/all users)`,
		Args: MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				// this error was not during the sync operation return as it is
				return err
			}
			cmd.Println(params.render(fmt.Sprintf("Operator %q", GetConfig().Operator), params.operator))
			sort.Strings(params.accounts)
			for _, v := range params.accounts {
				cmd.Println(params.render(fmt.Sprintf("Account %q", v), params.accountValidations[v]))
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.allAccounts, "all-accounts", "A", false, "validate all accounts under the current operator (exclusive of -a)")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createValidateCommand())
}

type ValidateCmdParams struct {
	AccountContextParams
	allAccounts        bool
	operator           *jwt.ValidationResults
	accounts           []string
	accountValidations map[string]*jwt.ValidationResults
}

func (p *ValidateCmdParams) SetDefaults(ctx ActionCtx) error {
	p.accountValidations = make(map[string]*jwt.ValidationResults)
	if p.allAccounts && p.Name != "" {
		return errors.New("specify only one of --account or --all-accounts")
	}

	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}

	c := GetConfig()
	accounts, err := c.ListAccounts()
	if err != nil {
		return err
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

func (p *ValidateCmdParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if !p.allAccounts {
		if err = p.AccountContextParams.Edit(ctx); err != nil {
			return err
		}
	}
	return err
}

func (p *ValidateCmdParams) Load(ctx ActionCtx) error {
	if !p.allAccounts {
		if err := p.AccountContextParams.Validate(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *ValidateCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ValidateCmdParams) validateJWT(claim jwt.Claims) *jwt.ValidationResults {
	var vr jwt.ValidationResults
	claim.Validate(&vr)
	if vr.IsEmpty() {
		return nil
	}
	return &vr
}

func (p *ValidateCmdParams) Validate(ctx ActionCtx) error {
	var err error
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	p.operator = p.validateJWT(oc)

	p.accounts, err = p.getSelectedAccounts()
	if err != nil {
		return err
	}

	for _, v := range p.accounts {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(v)
		if err != nil {
			return err
		}
		aci := p.validateJWT(ac)
		if aci != nil {
			p.accountValidations[v] = aci
		}
		if !oc.DidSign(ac) {
			if p.accountValidations[v] == nil {
				p.accountValidations[v] = &jwt.ValidationResults{}
			}
			p.accountValidations[v].AddError("Account is not signed by operator or operator signing keys")
		}
		users, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, v, store.Users)
		if err != nil {
			return err
		}
		for _, u := range users {
			uc, err := ctx.StoreCtx().Store.ReadUserClaim(v, u)
			if err != nil {
				return err
			}
			if uvr := p.validateJWT(uc); uvr != nil {
				for _, vi := range uvr.Issues {
					if p.accountValidations[v] == nil {
						p.accountValidations[v] = &jwt.ValidationResults{}
					}
					vi.Description = fmt.Sprintf("user %q: %s", u, vi.Description)
					p.accountValidations[v].Add(vi)
				}
			}
			if !ac.DidSign(uc) {
				if p.accountValidations[v] == nil {
					p.accountValidations[v] = &jwt.ValidationResults{}
				}
				p.accountValidations[v].AddError("user %q is not signed by account or account signing keys", u)
			}
		}
	}

	return nil
}

func (p *ValidateCmdParams) getSelectedAccounts() ([]string, error) {
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

func (p *ValidateCmdParams) Run(ctx ActionCtx) error {
	return nil
}

func (p *ValidateCmdParams) render(name string, issues *jwt.ValidationResults) string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle(fmt.Sprintf(name))
	if issues != nil {
		table.AddHeaders("#", "", "Description")
		for i, v := range issues.Issues {
			fatal := ""
			if v.Blocking || v.TimeCheck {
				fatal = "!"
			}
			table.AddRow(i+1, fatal, v.Description)
		}
	} else {
		table.AddRow("No issues found")
	}
	return table.Render()
}
