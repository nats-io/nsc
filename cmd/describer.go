/*
 * Copyright 2018 The NATS Authors
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
	"net/url"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/nats-io/jwt"
	"github.com/xlab/tablewriter"
)

type Describer interface {
	Describe() string
}

type AccountDescriber struct {
	jwt.AccountClaims
}

func NewAccountDescriber(ac jwt.AccountClaims) *AccountDescriber {
	return &AccountDescriber{AccountClaims: ac}
}

func (a *AccountDescriber) Describe() string {
	var buf bytes.Buffer

	table := tablewriter.CreateTable()
	table.UTF8Box()

	table.AddTitle("Account Details")
	table.AddRow("Name", a.Name)
	AddStandardClaimInfo(table, a.ClaimsData)

	if a.Subject != a.Issuer {
		lim := a.Limits
		if lim.Conn > 0 {
			table.AddRow("Max Connections", fmt.Sprintf("%d", lim.Conn))
		} else {
			table.AddRow("Max Connections", "Unlimited")
		}

		if lim.Data > 0 {
			table.AddRow("Max Data", humanize.Bytes(uint64(lim.Data)))
		} else {
			table.AddRow("Max Data", "Unlimited")
		}

		if lim.Exports > 0 {
			table.AddRow("Max Exports", fmt.Sprintf("%d", lim.Exports))
		} else {
			table.AddRow("Max Exports", "Unlimited")
		}

		if lim.Imports > 0 {
			table.AddRow("Max Imports", fmt.Sprintf("%d", lim.Imports))
		} else {
			table.AddRow("Max Imports", "Unlimited")
		}

		if lim.Payload > 0 {
			table.AddRow("Max Msg Payload", humanize.Bytes(uint64(lim.Payload)))
		} else {
			table.AddRow("Max Msg Payload", "Unlimited")
		}

		if lim.Subs > 0 {
			table.AddRow("Max Subscriptions", fmt.Sprintf("%d", lim.Subs))
		} else {
			table.AddRow("Max Subscriptions", "Unlimited")
		}
	}

	if len(a.Imports) == 0 {
		table.AddRow("Imports", "No services or streams imported")
	}

	if len(a.Exports) == 0 {
		table.AddRow("Exports", "No services or streams exported")
	}
	AddListValues(table, "Tags", a.Tags)

	buf.WriteString(table.Render())

	if len(a.Exports) > 0 {
		buf.WriteString("\n")
		buf.WriteString(NewExportsDescriber(a.Exports).Describe())
	}

	if len(a.Imports) > 0 {
		buf.WriteString("\n")
		buf.WriteString(NewImportsDescriber(a.Imports).Describe())
	}

	return buf.String()
}

type ExportsDescriber struct {
	jwt.Exports
}

func NewExportsDescriber(exports jwt.Exports) *ExportsDescriber {
	var e ExportsDescriber
	e.Exports = exports
	return &e
}

func (e *ExportsDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()

	table.AddTitle("Exports")
	table.AddHeaders("Type", "Subject", "Public")
	for _, v := range e.Exports {
		public := "Yes"
		if v.TokenReq {
			public = "No"
		}
		table.AddRow(strings.Title(v.Type.String()), v.Subject, public)
	}
	return table.Render()
}

type ImportsDescriber struct {
	jwt.Imports
}

func NewImportsDescriber(imports jwt.Imports) *ImportsDescriber {
	var d ImportsDescriber
	d.Imports = imports
	return &d
}

func (i *ImportsDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.AddTitle("Imports")
	table.AddHeaders("Type", "Subject", "To", "Expires")

	for _, v := range i.Imports {
		NewImportDescriber(*v).Brief(table)
	}

	return table.Render()
}

type ImportDescriber struct {
	jwt.Import
}

func NewImportDescriber(im jwt.Import) *ImportDescriber {
	return &ImportDescriber{im}
}

func (i *ImportDescriber) Brief(table *tablewriter.Table) {
	expiration := ""
	ac, err := i.LoadActivation()
	if err != nil {
		expiration = fmt.Sprintf("error decoding: %v", err.Error())
	} else {
		expiration = fmt.Sprintf("%s (%s)", UnixToDate(ac.Expires), HumanizedDate(ac.Expires))
	}
	table.AddRow(strings.Title(i.Type.String()), string(i.Subject), string(i.To), expiration)
}

func (i *ImportDescriber) IsRemoteImport() bool {
	if url, err := url.Parse(i.Token); err == nil && url.Scheme != "" {
		return true
	}
	return false
}

func (i *ImportDescriber) LoadActivation() (*jwt.ActivationClaims, error) {
	var token string
	if i.IsRemoteImport() {
		d, err := LoadFromURL(i.Token)
		if err != nil {
			return nil, err
		}
		token = string(d)
	} else {
		token = i.Token
	}
	return jwt.DecodeActivationClaims(token)
}

func AddStandardClaimInfo(table *tablewriter.Table, cd jwt.ClaimsData) {
	table.AddRow("Account ID", cd.Subject)
	table.AddRow("Issuer ID", cd.Issuer)
	table.AddRow("Issued", fmt.Sprintf("%s (%s)", UnixToDate(cd.IssuedAt), HumanizedDate(cd.IssuedAt)))

	if cd.Expires > 0 {
		table.AddRow("Expires", fmt.Sprintf("%s (%s)", UnixToDate(cd.Expires), HumanizedDate(cd.Expires)))
	} else {
		table.AddRow("Expires", "No expiration")
	}
}

type ActivationDescriber struct {
	jwt.ActivationClaims
}

func NewActivationDescriber(a jwt.ActivationClaims) *ActivationDescriber {
	return &ActivationDescriber{ActivationClaims: a}
}

func (c *ActivationDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Activation")
	table.AddRow("Import Type", strings.Title(c.ImportType.String()))
	table.AddRow("Import Subject", string(c.ImportSubject))

	AddStandardClaimInfo(table, c.ActivationClaims.ClaimsData)

	AddLimits(table, c.Limits)

	return table.Render()
}

func AddLimits(table *tablewriter.Table, lim jwt.Limits) {
	if lim.Max > 0 {
		table.AddRow("Max Messages", fmt.Sprintf("%d", lim.Max))
	} else {
		table.AddRow("Max Messages", "Unlimited")
	}

	if lim.Payload > 0 {
		table.AddRow("Max Msg Payload", humanize.Bytes(uint64(lim.Payload)))
	} else {
		table.AddRow("Max Msg Payload", "Unlimited")
	}

	if lim.Src != "" {
		table.AddRow("Network Src", lim.Src)
	} else {
		table.AddRow("Network Src", "Any")
	}

	if len(lim.Times) > 0 {
		for i, v := range lim.Times {
			if i == 0 {
				table.AddRow("Time", fmt.Sprintf("%s-%s", v.Start, v.End))
			} else {
				table.AddRow("", fmt.Sprintf("%s-%s", v.Start, v.End))
			}
		}
	} else {
		table.AddRow("Time", "Any")
	}
}

func AddListValues(table *tablewriter.Table, label string, subjects []string) {
	if len(subjects) > 0 {
		for i, v := range subjects {
			if i == 0 {
				table.AddRow(label, string(v))
			} else {
				table.AddRow("", string(v))
			}
		}
	}
}

type UserDescriber struct {
	jwt.UserClaims
}

func NewUserDescriber(u jwt.UserClaims) *UserDescriber {
	return &UserDescriber{UserClaims: u}
}

func (u *UserDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("User")
	table.AddRow("Name", u.Name)
	table.AddRow("User ID", u.Subject)
	AddListValues(table, "Pub Allow", u.Pub.Allow)
	AddListValues(table, "Pub Deny", u.Pub.Deny)
	AddListValues(table, "Sub Allow", u.Sub.Allow)
	AddListValues(table, "Sub Deny", u.Sub.Deny)

	AddLimits(table, u.Limits)

	table.AddRow("Issued", fmt.Sprintf("%s (%s)", UnixToDate(u.IssuedAt), HumanizedDate(u.IssuedAt)))
	if u.Expires > 0 {
		table.AddRow("Expires", fmt.Sprintf("%s (%s)", UnixToDate(u.Expires), HumanizedDate(u.Expires)))
	} else {
		table.AddRow("Expires", "No expiration")
	}
	AddListValues(table, "Tags", u.Tags)

	return table.Render()
}

type ClusterDescriber struct {
	jwt.ClusterClaims
}

func NewClusterDescriber(c jwt.ClusterClaims) *ClusterDescriber {
	return &ClusterDescriber{ClusterClaims: c}
}

func (c *ClusterDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Cluster")
	table.AddRow("Name", c.Name)
	table.AddRow("Cluster ID", c.Subject)

	AddListValues(table, "Trusted Operators", c.Trust)
	if c.OperatorURL != "" {
		table.AddRow("Operator Srv", c.OperatorURL)
	}

	AddListValues(table, "Trusted Accounts", c.Accounts)
	if c.AccountURL != "" {
		table.AddRow("Account Srv", c.AccountURL)
	}

	table.AddRow("Issued", fmt.Sprintf("%s (%s)", UnixToDate(c.IssuedAt), HumanizedDate(c.IssuedAt)))
	if c.Expires > 0 {
		table.AddRow("Expires", fmt.Sprintf("%s (%s)", UnixToDate(c.Expires), HumanizedDate(c.Expires)))
	} else {
		table.AddRow("Expires", "No expiration")
	}

	AddListValues(table, "Tags", c.Tags)

	return table.Render()
}

type ServerDescriber struct {
	jwt.ServerClaims
}

func NewServerDescriber(u jwt.ServerClaims) *ServerDescriber {
	return &ServerDescriber{ServerClaims: u}
}

func (s *ServerDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Server")
	table.AddRow("Name", s.Name)
	table.AddRow("Server ID", s.Subject)

	table.AddRow("Issued", fmt.Sprintf("%s (%s)", UnixToDate(s.IssuedAt), HumanizedDate(s.IssuedAt)))
	if s.Expires > 0 {
		table.AddRow("Expires", fmt.Sprintf("%s (%s)", UnixToDate(s.Expires), HumanizedDate(s.Expires)))
	} else {
		table.AddRow("Expires", "No expiration")
	}
	AddListValues(table, "Tags", s.Tags)

	return table.Render()
}

type OperatorDescriber struct {
	jwt.OperatorClaims
}

func NewOperatorDescriber(o jwt.OperatorClaims) *OperatorDescriber {
	return &OperatorDescriber{OperatorClaims: o}
}

func (o *OperatorDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Operator")
	table.AddRow("Name", o.Name)
	table.AddRow("Operator ID", o.Subject)

	if len(o.Identities) > 0 {
		for _, v := range o.Identities {
			table.AddRow(fmt.Sprintf("ID %s", v.ID), v.Proof)
		}
	}

	AddListValues(table, "Signing Keys", o.SigningKeys)

	table.AddRow("Issued", fmt.Sprintf("%s (%s)", UnixToDate(o.IssuedAt), HumanizedDate(o.IssuedAt)))
	if o.Expires > 0 {
		table.AddRow("Expires", fmt.Sprintf("%s (%s)", UnixToDate(o.Expires), HumanizedDate(o.Expires)))
	} else {
		table.AddRow("Expires", "No expiration")
	}
	AddListValues(table, "Tags", o.Tags)

	return table.Render()
}
