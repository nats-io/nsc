/*
 *
 *  * Copyright 2018-2019 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
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
	AddStandardClaimInfo(table, &a.AccountClaims)
	table.AddSeparator()

	if len(a.SigningKeys) > 0 {
		AddListValues(table, "Signing Keys", ShortCodesList(a.SigningKeys))
		table.AddSeparator()
	}

	lim := a.Limits
	if lim.Conn > -1 {
		table.AddRow("Max Connections", fmt.Sprintf("%d", lim.Conn))
	} else {
		table.AddRow("Max Connections", "Unlimited")
	}

	if lim.Data > -1 {
		table.AddRow("Max Data", fmt.Sprintf("%s (%d bytes)", humanize.Bytes(uint64(lim.Data)), lim.Data))
	} else {
		table.AddRow("Max Data", "Unlimited")
	}

	if lim.Exports > -1 {
		table.AddRow("Max Exports", fmt.Sprintf("%d", lim.Exports))
	} else {
		table.AddRow("Max Exports", "Unlimited")
	}

	if lim.Imports > -1 {
		table.AddRow("Max Imports", fmt.Sprintf("%d", lim.Imports))
	} else {
		table.AddRow("Max Imports", "Unlimited")
	}

	if lim.Payload > -1 {
		table.AddRow("Max Msg Payload", fmt.Sprintf("%s (%d bytes)", humanize.Bytes(uint64(lim.Payload)), lim.Payload))
	} else {
		table.AddRow("Max Msg Payload", "Unlimited")
	}

	if lim.Subs > -1 {
		table.AddRow("Max Subscriptions", fmt.Sprintf("%d", lim.Subs))
	} else {
		table.AddRow("Max Subscriptions", "Unlimited")
	}

	we := "False"
	if lim.WildcardExports {
		we = "True"
	}
	table.AddRow("Exports Allows Wildcards", we)

	table.AddSeparator()

	if len(a.Imports) == 0 {
		table.AddRow("Imports", "None")
	}

	if len(a.Exports) == 0 {
		table.AddRow("Exports", "None")
	}

	if len(a.Tags) > 0 {
		table.AddSeparator()
		AddListValues(table, "Tags", a.Tags)
	}

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
	table.AddHeaders("Name", "Type", "Subject", "Public")
	for _, v := range e.Exports {
		public := "Yes"
		if v.TokenReq {
			public = "No"
		}
		table.AddRow(v.Name, strings.Title(v.Type.String()), v.Subject, public)
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
	table.AddHeaders("Name", "Type", "Remote", "Local", "Expires", "From Account", "Public")

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
	local := string(i.To)
	remote := string(i.Subject)

	if i.Type == jwt.Service {
		local, remote = remote, local
	}

	if i.Token == "" {
		table.AddRow(i.Name, strings.Title(i.Type.String()), remote, local, "", ShortCodes(i.Account), "Yes")
		return
	}
	expiration := ""
	ac, err := i.LoadActivation()
	if err != nil {
		expiration = fmt.Sprintf("error decoding: %v", err.Error())
	} else {
		expiration = RenderDate(ac.Expires)
	}
	table.AddRow(i.Name, strings.Title(i.Type.String()), remote, local, expiration, ShortCodes(i.Account), "No")
}

func (i *ImportDescriber) IsRemoteImport() bool {
	if u, err := url.Parse(i.Token); err == nil && u.Scheme != "" {
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

func AddStandardClaimInfo(table *tablewriter.Table, claims jwt.Claims) {
	label := "Account ID"
	issuer := ""
	if ac, ok := claims.(*jwt.ActivationClaims); ok {
		if ac.IssuerAccount != "" {
			issuer = ac.IssuerAccount
		}
	}
	if acc, ok := claims.(*jwt.ActivationClaims); ok {
		if acc.IssuerAccount != "" {
			issuer = acc.IssuerAccount
		}
	}
	if uc, ok := claims.(*jwt.UserClaims); ok {
		label = "User ID"
		if uc.IssuerAccount != "" {
			issuer = uc.IssuerAccount
		}
	}

	cd := claims.Claims()
	if cd.Name != "" {
		table.AddRow("Name", cd.Name)
	}
	table.AddRow(label, ShortCodes(cd.Subject))
	table.AddRow("Issuer ID", ShortCodes(cd.Issuer))
	if issuer != "" {
		table.AddRow("Issuer Account", ShortCodes(issuer))
	}
	table.AddRow("Issued", RenderDate(cd.IssuedAt))
	table.AddRow("Expires", RenderDate(cd.Expires))
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
	AddStandardClaimInfo(table, &c.ActivationClaims)
	table.AddSeparator()
	table.AddRow("Import Type", strings.Title(c.ImportType.String()))
	table.AddRow("Import Subject", string(c.ImportSubject))
	table.AddSeparator()

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
	AddStandardClaimInfo(table, &u.UserClaims)

	if len(u.Pub.Allow) > 0 || len(u.Pub.Deny) > 0 ||
		len(u.Sub.Allow) > 0 || len(u.Sub.Deny) > 0 {
		table.AddSeparator()
		AddListValues(table, "Pub Allow", u.Pub.Allow)
		AddListValues(table, "Pub Deny", u.Pub.Deny)
		AddListValues(table, "Sub Allow", u.Sub.Allow)
		AddListValues(table, "Sub Deny", u.Sub.Deny)
	}

	table.AddSeparator()
	AddLimits(table, u.Limits)

	if len(u.Tags) > 0 {
		table.AddSeparator()
		AddListValues(table, "Tags", u.Tags)
	}

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
	table.AddRow("Cluster ID", ShortCodes(c.Subject))
	table.AddRow("Issuer ID", ShortCodes(c.Issuer))
	table.AddRow("Issued", RenderDate(c.IssuedAt))
	table.AddRow("Expires", RenderDate(c.Expires))

	table.AddSeparator()

	AddListValues(table, "Trusted Operators", c.Trust)
	if c.OperatorURL != "" {
		table.AddRow("Operator Srv", c.OperatorURL)
	}

	table.AddSeparator()

	AddListValues(table, "Trusted Accounts", c.Accounts)
	if c.AccountURL != "" {
		table.AddRow("Account Srv", c.AccountURL)
	}

	table.AddSeparator()
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
	table.AddRow("Server ID", ShortCodes(s.Subject))
	table.AddRow("Issuer ID", ShortCodes(s.Issuer))
	table.AddRow("Issued", RenderDate(s.IssuedAt))
	table.AddRow("Expires", RenderDate(s.Expires))

	table.AddSeparator()

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
	table.AddTitle("Operator Details")
	table.AddRow("Name", o.Name)
	table.AddRow("Operator ID", ShortCodes(o.Subject))
	table.AddRow("Issued", RenderDate(o.IssuedAt))
	table.AddRow("Expires", RenderDate(o.Expires))

	if len(o.Identities) > 0 {
		table.AddSeparator()
		for _, v := range o.Identities {
			table.AddRow(fmt.Sprintf("ID %s", v.ID), v.Proof)
		}
	}

	if len(o.SigningKeys) > 0 {
		table.AddSeparator()
		AddListValues(table, "Signing Keys", ShortCodesList(o.SigningKeys))
	}

	if len(o.Tags) > 0 {
		table.AddSeparator()
		AddListValues(table, "Tags", o.Tags)
	}

	return table.Render()
}

func ShortCodesList(keys []string) []string {
	var short []string
	if len(keys) > 0 {
		for _, v := range keys {
			short = append(short, ShortCodes(v))
		}
	}
	return short
}
