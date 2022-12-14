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
	"os"
	"sort"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/xlab/tablewriter"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createValidateCommand() *cobra.Command {
	var params ValidateCmdParams
	var cmd = &cobra.Command{
		Short:   "Validate an operator, account(s), and users",
		Example: "validate",
		Use: `validate (current operator/current account/account users)
validate -a <accountName> (current operator/<accountName>/account users)
validate -A (current operator/all accounts/all users)
validate -f <file>`,
		Args: MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = false
			if err := RunAction(cmd, args, &params); err != nil {
				// this error was not during the sync operation return as it is
				return err
			}
			cmd.Println(params.render(fmt.Sprintf("Operator %q", GetConfig().Operator), params.operator))
			sort.Strings(params.accounts)
			for _, v := range params.accounts {
				cmd.Println(params.render(fmt.Sprintf("Account %q", v), params.accountValidations[v]))
			}

			if params.foundErrors() {
				cmd.SilenceUsage = true
				return errors.New("validation found errors")
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.allAccounts, "all-accounts", "A", false, "validate all accounts under the current operator (exclusive of -a and -f)")
	cmd.Flags().StringVarP(&params.file, "file", "f", "", "validate all jwt (separated by newline) in the provided file (exclusive of -a and -A)")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createValidateCommand())
}

type ValidateCmdParams struct {
	AccountContextParams
	allAccounts        bool
	file               string
	operator           *jwt.ValidationResults
	accounts           []string
	accountValidations map[string]*jwt.ValidationResults
}

func (p *ValidateCmdParams) SetDefaults(ctx ActionCtx) error {
	p.accountValidations = make(map[string]*jwt.ValidationResults)
	if p.allAccounts && p.Name != "" {
		return errors.New("specify only one of --account or --all-accounts")
	}
	if p.file != "" {
		if p.allAccounts || p.Name != "" {
			return errors.New("specify only one of --account or --all-accounts or --file")
		}
	} else {
		// if they specified an account name, this will validate it
		if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (p *ValidateCmdParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if !p.allAccounts && p.file == "" {
		if err = p.AccountContextParams.Edit(ctx); err != nil {
			return err
		}
	}
	return err
}

func (p *ValidateCmdParams) Load(ctx ActionCtx) error {
	if !p.allAccounts && p.Name != "" {
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
	if p.file != "" {
		return p.validateFile(ctx)
	}
	return p.validate(ctx)
}

func (p *ValidateCmdParams) validateFile(ctx ActionCtx) error {
	f, err := os.ReadFile(p.file)
	if err != nil {
		return err
	}
	type entry struct {
		issue jwt.ValidationIssue
		cnt   int
	}
	summary := map[string]*entry{}
	lines := strings.Split(string(f), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// cut off what is a result of pack
		if i := strings.Index(l, "|"); i != -1 {
			l = l[i+1:]
		}
		c, err := jwt.Decode(l)
		if err != nil {
			return fmt.Errorf("claim decoding error: '%v' claim: '%v'", err, l)
		}
		subj := c.Claims().Subject
		vr := jwt.ValidationResults{}
		c.Validate(&vr)
		if _, ok := p.accountValidations[subj]; !ok {
			p.accountValidations[subj] = &jwt.ValidationResults{}
			p.accounts = append(p.accounts, subj)
		}
		for _, vi := range vr.Issues {
			p.accountValidations[subj].Add(vi)
			if val, ok := summary[vi.Description]; !ok {
				summary[vi.Description] = &entry{*vi, 1}
			} else {
				val.cnt++
			}
		}
	}
	if len(p.accounts) > 1 {
		summaryAcc := "summary of all accounts"
		p.accounts = append(p.accounts, summaryAcc)
		vr := &jwt.ValidationResults{}
		p.accountValidations[summaryAcc] = vr
		for _, v := range summary {
			iss := v.issue
			iss.Description = fmt.Sprintf("%s (%d occurrences)", iss.Description, v.cnt)
			vr.Add(&iss)
		}
	}
	return nil
}

func (p *ValidateCmdParams) validate(ctx ActionCtx) error {
	var err error
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	p.operator = p.validateJWT(oc)
	if !oc.DidSign(oc) {
		if p.operator == nil {
			p.operator = &jwt.ValidationResults{}
		}
		p.operator.AddError("operator is not issued by operator or operator signing key")
	}

	p.accounts, err = p.getSelectedAccounts()
	if err != nil {
		return err
	}

	for _, v := range p.accounts {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(v)
		if err != nil {
			if store.IsNotExist(err) {
				continue
			}
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
			p.accountValidations[v].AddError("Account is not issued by operator or operator signing keys")
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
				p.accountValidations[v].AddError("user %q is not issued by account or account signing keys", u)
			} else if oc.StrictSigningKeyUsage && uc.Issuer == ac.Subject {
				p.accountValidations[v].AddError("user %q is issued by account key but operator is in strict mode", u)
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
	} else if p.Name != "" {
		return []string{p.AccountContextParams.Name}, nil
	}
	return nil, nil
}

func (p *ValidateCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	return nil, nil
}

func (p *ValidateCmdParams) foundErrors() bool {
	var reports []*jwt.ValidationResults
	if p.operator != nil {
		reports = append(reports, p.operator)
	}
	for _, v := range p.accounts {
		vr := p.accountValidations[v]
		if vr != nil {
			reports = append(reports, vr)
		}
	}
	for _, r := range reports {
		for _, ri := range r.Issues {
			if ri.Blocking || ri.TimeCheck {
				return true
			}
		}
	}
	return false
}

func (p *ValidateCmdParams) render(name string, issues *jwt.ValidationResults) string {
	table := tablewriter.CreateTable()
	table.AddTitle(name)
	if issues != nil {
		table.AddHeaders("#", " ", "Description")
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
