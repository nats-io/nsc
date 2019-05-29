/*
 * Copyright 2019 The NATS Authors
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
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createGenerateNkeyConfigCmd() *cobra.Command {
	var params GenerateNkeyConfigParams
	cmd := &cobra.Command{
		Use:          "nkeyconfig",
		Short:        "Generate an account config file for an operator",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate nkeyconfig`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() && params.out != "--" {
				cmd.Printf("Success!! - generated %q\n", params.out)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateNkeyConfigCmd())
}

type GenerateNkeyConfigParams struct {
	out string
}

func (p *GenerateNkeyConfigParams) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNkeyConfigParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNkeyConfigParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNkeyConfigParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNkeyConfigParams) Validate(ctx ActionCtx) error {
	if ctx.StoreCtx().Operator.Name == "" {
		return errors.New("set an operator first - 'nsc env --operator <name>'")
	}
	return nil
}

func (p *GenerateNkeyConfigParams) Run(ctx ActionCtx) error {
	builder := NewConfigBuilder()

	names, err := GetConfig().ListAccounts()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("operator %q has no accounts", GetConfig().Operator)
	}

	s := ctx.StoreCtx().Store
	for _, n := range names {
		ac, err := s.ReadAccountClaim(n)
		if err != nil {
			return err
		}
		builder.Add(ac)

		users, err := s.ListEntries(store.Accounts, n, store.Users)
		for _, u := range users {
			uc, err := s.ReadUserClaim(n, u)
			if err != nil {
				return err
			}
			builder.Add(uc)
		}
	}

	d, err := builder.Generate()
	if err != nil {
		return err
	}

	return Write("--", d)

}

type ConfigBuilder struct {
	accounts            accounts
	accountToName       map[string]string
	accountClaims       map[string]*jwt.AccountClaims
	userClaims          map[string][]*jwt.UserClaims
	srcToPrivateImports map[string][]jwt.Import
}

func NewConfigBuilder() *ConfigBuilder {
	cb := ConfigBuilder{}
	cb.accounts.Accounts = make(map[string]account)
	cb.accountToName = make(map[string]string)
	cb.accountClaims = make(map[string]*jwt.AccountClaims)
	cb.userClaims = make(map[string][]*jwt.UserClaims)
	cb.srcToPrivateImports = make(map[string][]jwt.Import)
	return &cb
}

func (cb *ConfigBuilder) Add(c jwt.Claims) {
	ac, ok := c.(*jwt.AccountClaims)
	if ok {
		cb.addAccountClaim(ac)
		return
	}
	uc, ok := c.(*jwt.UserClaims)
	if ok {
		cb.addUserClaim(uc)
		return
	}
}

func (cb *ConfigBuilder) addAccountClaim(ac *jwt.AccountClaims) {
	cb.accountClaims[ac.Subject] = ac
	cb.accountToName[ac.Subject] = ac.Name
	for _, i := range ac.Imports {
		if i.Token != "" {
			imps := cb.srcToPrivateImports[i.Account]
			if imps == nil {
				imps = make([]jwt.Import, 0)
			}
			imps = append(imps, *i)
			cb.srcToPrivateImports[i.Account] = imps
		}
	}
}

func (cb *ConfigBuilder) addUserClaim(uc *jwt.UserClaims) {
	apk := uc.Issuer
	if uc.IssuerAccount != "" {
		apk = uc.IssuerAccount
	}
	users := cb.userClaims[apk]
	if users == nil {
		users = []*jwt.UserClaims{}
	}
	users = append(users, uc)
	cb.userClaims[apk] = users
}

func (cb *ConfigBuilder) Generate() ([]byte, error) {
	if err := cb.parse(); err != nil {
		return nil, err
	}
	return cb.serialize()
}

func (cb *ConfigBuilder) parse() error {
	for _, ac := range cb.accountClaims {
		var a account
		users := cb.userClaims[ac.Subject]
		for _, uc := range users {
			a.Users = append(a.Users, user{Nkey: uc.Subject})
		}

		for _, exports := range ac.Exports {
			var e export
			if exports.IsStream() {
				e.Stream = exports.Subject
			} else {
				e.Service = exports.Subject
			}

			if exports.TokenReq {
				imprts := cb.srcToPrivateImports[ac.Subject]
				if imprts != nil {
					for _, imprt := range imprts {
						if imprt.Type == exports.Type && imprt.Subject.IsContainedIn(exports.Subject) {
							an := cb.accountToName[imprt.Account]
							e.Accounts = append(e.Accounts, an)
						}

					}
				}
			}
			a.Exports = append(a.Exports, e)
		}

		for _, x := range ac.Imports {
			var e imprt
			var src source
			src.Subject = x.Subject
			src.Account = cb.accountToName[x.Account]
			if src.Account == "" {
				return fmt.Errorf("unable to resolve account %q in import under current operator", x.Account)
			}
			if x.IsStream() {
				e.Stream = &src
				if x.To != "" {
					e.Prefix = x.To
				}
			} else {
				e.Service = &src
				if x.To != "" {
					e.To = x.To
				}
			}
			a.Imports = append(a.Imports, e)
		}

		cb.accounts.Accounts[ac.Name] = a
	}
	return nil
}

func (cb *ConfigBuilder) serialize() ([]byte, error) {
	return []byte(cb.accounts.String()), nil
}

type accounts struct {
	Accounts map[string]account `json:"accounts,omitempty"`
}

func (a *accounts) String() string {
	var buf bytes.Buffer
	buf.WriteString("accounts: {\n")
	for k, v := range a.Accounts {
		buf.WriteString(fmt.Sprintf("  %s: {\n", k))
		buf.WriteString(v.String())
		buf.WriteString("  }\n")
	}
	buf.WriteString("}\n")
	return buf.String()
}

type account struct {
	Users   []user   `json:"users,omitempty"`
	Exports []export `json:"exports,omitempty"`
	Imports []imprt  `json:"imports,omitempty"`
}

func (a *account) String() string {
	var buf bytes.Buffer

	if len(a.Users) > 0 {
		buf.WriteString("    users: [\n")
		for _, u := range a.Users {
			buf.WriteString(fmt.Sprintf("      %s\n", u.String()))
		}
		buf.WriteString("    ]\n")
	}

	if len(a.Exports) > 0 {
		buf.WriteString("    exports: [\n")
		for _, e := range a.Exports {
			buf.WriteString(fmt.Sprintf("      %s\n", e.String()))
		}
		buf.WriteString("    ]\n")
	}
	if len(a.Imports) > 0 {
		buf.WriteString("    imports: [\n")
		for _, i := range a.Imports {
			buf.WriteString(fmt.Sprintf("      %s\n", i.String()))
		}
		buf.WriteString("    ]\n")
	}
	return buf.String()
}

type user struct {
	Nkey string `json:"nkey,omitempty"`
}

func (u *user) String() string {
	return fmt.Sprintf("{ nkey: %s }", u.Nkey)
}

type export struct {
	Stream   jwt.Subject `json:"stream,omitempty"`
	Service  jwt.Subject `json:"service,omitempty"`
	Accounts []string    `json:"accounts,omitempty"`
}

func (ex *export) String() string {
	var buf bytes.Buffer
	buf.WriteString("{ ")
	if ex.Stream != "" {
		buf.WriteString("stream: ")
		buf.WriteString(string(ex.Stream))
	} else {
		buf.WriteString("service: ")
		buf.WriteString(string(ex.Service))
	}
	if len(ex.Accounts) > 0 {
		buf.WriteString(", accounts: [")
		buf.WriteString(strings.Join(ex.Accounts, ","))
		buf.WriteString("]")
	}
	buf.WriteString(" }")
	return buf.String()
}

type source struct {
	Account string      `json:"account,omitempty"`
	Subject jwt.Subject `json:"subject,omitempty"`
}

func (s *source) String() string {
	return fmt.Sprintf("{ account: %s, subject: %s }", s.Account, string(s.Subject))
}

type imprt struct {
	Stream  *source     `json:"stream,omitempty"`
	Service *source     `json:"service,omitempty"`
	Prefix  jwt.Subject `json:"prefix,omitempty"`
	To      jwt.Subject `json:"to,omitempty"`
}

func (im *imprt) String() string {
	var buf bytes.Buffer
	buf.WriteString("{ ")
	if im.Service != nil {
		buf.WriteString("service: ")
		buf.WriteString(im.Service.String())
		if im.To != "" {
			buf.WriteString(", to: ")
			buf.WriteString(string(im.To))
		}
	} else {
		buf.WriteString("stream: ")
		buf.WriteString(im.Stream.String())
		if im.Prefix != "" {
			buf.WriteString(", prefix: ")
			buf.WriteString(string(im.Prefix))
		}
	}
	buf.WriteString("}")

	return buf.String()
}
