/*
 * Copyright 2018-2024 The NATS Authors
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
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/nats-io/jwt/v2"
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
	table.AddTitle("Account Details")
	AddStandardClaimInfo(table, &a.AccountClaims)
	table.AddSeparator()

	info := false
	if a.Description != "" {
		table.AddRow("Description", strings.ReplaceAll(a.Description, "\n", " "))
		info = true
	}
	if a.InfoURL != "" {
		table.AddRow("Info Url", a.InfoURL)
		info = true
	}
	if info {
		table.AddSeparator()
	}

	if len(a.SigningKeys) > 0 {
		AddListValues(table, "Signing Keys", a.SigningKeys.Keys())
		table.AddSeparator()
	}

	if len(a.Authorization.AuthUsers) > 0 {
		AddListValues(table, "Auth Callout Users", a.Authorization.AuthUsers)
		if len(a.Authorization.AllowedAccounts) > 0 {
			AddListValues(table, "Allowed Accounts", a.Authorization.AllowedAccounts)
		}
		if a.Authorization.XKey != "" {
			table.AddRow("Encrypt For", a.Authorization.XKey)
		}
		table.AddSeparator()
	}

	addLimitRow := func(table *tablewriter.Table, name string, limit int64, inBytes bool) {
		if limit > -1 {
			val := fmt.Sprintf("%d", limit)
			if inBytes {
				val = fmt.Sprintf("%s (%d bytes)", humanize.Bytes(uint64(limit)), limit)
			}
			table.AddRow(name, val)
		} else {
			table.AddRow(name, "Unlimited")
		}
	}

	lim := a.Limits
	addLimitRow(table, "Max Connections", lim.Conn, false)

	if lim.LeafNodeConn == 0 {
		table.AddRow("Max Leaf Node Connections", "Not Allowed")
	} else if lim.LeafNodeConn > 0 {
		table.AddRow("Max Leaf Node Connections", fmt.Sprintf("%d", lim.LeafNodeConn))
	} else {
		table.AddRow("Max Leaf Node Connections", "Unlimited")
	}

	addLimitRow(table, "Max Data", lim.Data, true)
	addLimitRow(table, "Max Exports", lim.Exports, false)
	addLimitRow(table, "Max Imports", lim.Imports, false)
	addLimitRow(table, "Max Msg Payload", lim.Payload, true)
	addLimitRow(table, "Max Subscriptions", lim.Subs, false)

	addBoolLimitRow := func(table *tablewriter.Table, msg string, value bool) {
		we := "False"
		if value {
			we = "True"
		}
		table.AddRow(msg, we)
	}

	addBoolLimitRow(table, "Exports Allows Wildcards", lim.WildcardExports)
	addBoolLimitRow(table, "Disallow Bearer Token", lim.DisallowBearer)

	AddPermissions(table, a.DefaultPermissions)

	printJsLimit := func(lim jwt.JetStreamLimits) {
		switch {
		case lim.DiskStorage > 0:
			table.AddRow("Max Disk Storage", humanize.Bytes(uint64(lim.DiskStorage)))
		case lim.DiskStorage == 0:
			table.AddRow("Max Disk Storage", "Disabled")
		default:
			table.AddRow("Max Disk Storage", "Unlimited")
		}
		switch {
		case lim.MemoryStorage > 0:
			table.AddRow("Max Mem Storage", humanize.Bytes(uint64(lim.MemoryStorage)))
		case lim.MemoryStorage == 0:
			table.AddRow("Max Mem Storage", "Disabled")
		default:
			table.AddRow("Max Mem Storage", "Unlimited")
		}
		addLimitRow(table, "Max Streams", lim.Streams, false)
		addLimitRow(table, "Max Consumer", lim.Consumer, false)
		switch {
		case lim.MaxAckPending > 0:
			addLimitRow(table, "Max Ack Pending", lim.MaxAckPending, false)
		default:
			table.AddRow("Max Ack Pending", "Consumer Setting")
		}
		addLimitRow(table, "Max Ack Pending", lim.MaxAckPending, false)
		maxBytes := "optional (Stream setting)"
		if lim.MaxBytesRequired {
			maxBytes = "required (Stream setting)"
		}
		table.AddRow("Max Bytes", maxBytes)

		addLimitRow(table, "Max Memory Stream", lim.MemoryMaxStreamBytes, true)
		addLimitRow(table, "Max Disk Stream", lim.DiskMaxStreamBytes, true)
	}

	table.AddSeparator()
	if !a.Limits.IsJSEnabled() {
		table.AddRow("Jetstream", "Disabled")
	} else if len(a.Limits.JetStreamTieredLimits) == 0 {
		table.AddRow("Jetstream", "Enabled")
		printJsLimit(a.Limits.JetStreamLimits)
	} else {
		remaining := len(a.Limits.JetStreamTieredLimits)
		for tier, lim := range a.Limits.JetStreamTieredLimits {
			table.AddRow("Jetstream Tier", tier)
			printJsLimit(lim)
			remaining--
			if remaining != 0 {
				table.AddSeparator()
			}
		}
	}

	table.AddSeparator()

	if len(a.Imports) == 0 {
		table.AddRow("Imports", "None")
	}

	if len(a.Exports) == 0 {
		table.AddRow("Exports", "None")
	}

	if len(a.Revocations) != 0 {
		table.AddSeparator()
		table.AddRow("Revocations", fmt.Sprintf("%d", len(a.Revocations)))
	}

	table.AddSeparator()
	if a.Trace == nil {
		table.AddRow("Tracing Context", "Disabled")
	} else {
		table.AddRow("Tracing Context", "Enabled")
		table.AddRow("Subject", a.Trace.Destination)
		if a.Trace.Sampling == 0 {
			table.AddRow("Sampling", "100%")
		} else {
			table.AddRow("Sampling", fmt.Sprintf("%d%%", a.Trace.Sampling))
		}
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

	if len(a.Mappings) > 0 {
		buf.WriteString("\n")
		buf.WriteString(NewMappingsDescriber(a.Mappings).Describe())
	}

	if len(a.SigningKeys) > 0 {
		for _, v := range a.SigningKeys {
			if v == nil {
				continue
			}
			buf.WriteString("\n")
			buf.WriteString(NewScopedSkDescriber(v.(*jwt.UserScope)).Describe())
		}
		table.AddSeparator()
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

func toYesNo(tf bool) string {
	v := "Yes"
	if !tf {
		v = "No"
	}
	return v
}

func (e *ExportsDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.AddTitle("Exports")
	table.AddHeaders("Name", "Type", "Subject", "Account Token Position", "Public", "Revocations", "Tracking", "Allow Trace")
	for _, v := range e.Exports {
		mon := "N/A"
		rt := ""
		if v.Type == jwt.Service {
			if v.Latency != nil {
				mon = fmt.Sprintf("%s (%d%%)", v.Latency.Results, v.Latency.Sampling)
			} else {
				mon = "-"
			}
			switch v.ResponseType {
			case jwt.ResponseTypeStream:
				rt = fmt.Sprintf(" [%s]", jwt.ResponseTypeStream)
			case jwt.ResponseTypeChunked:
				rt = fmt.Sprintf(" [%s]", jwt.ResponseTypeChunked)
			}
		}

		st := TitleCase(v.Type.String())
		k := fmt.Sprintf("%s%s", st, rt)

		tp := "-"
		if v.AccountTokenPosition > 0 {
			tp = strconv.Itoa(int(v.AccountTokenPosition))
		}

		table.AddRow(v.Name, k, v.Subject, tp, toYesNo(!v.TokenReq), len(v.Revocations), mon, toYesNo(v.AllowTrace))
	}

	tableDesc := tablewriter.CreateTable()
	tableDesc.AddTitle("Exports - Descriptions")
	tableDesc.AddHeaders("Name", "Description", "Info Url")
	hasContent := false
	for _, v := range e.Exports {
		if v.Description == "" && v.InfoURL == "" {
			continue
		}
		hasContent = true
		tableDesc.AddRow(v.Name, strings.ReplaceAll(v.Description, "\n", " "), v.InfoURL)
	}

	ret := table.Render()
	if hasContent {
		ret = fmt.Sprintf("%s\n%s", ret, tableDesc.Render())
	}

	return ret
}

type MappingsDescriber jwt.Mapping

func NewMappingsDescriber(m jwt.Mapping) *MappingsDescriber {
	d := MappingsDescriber(m)
	return &d
}

func (i *MappingsDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.AddTitle("Mappings")
	table.AddHeaders("From", "To", "Weight (%)")
	for k, v := range *i {
		wSum := uint8(0)
		for i, m := range v {
			wSum += m.GetWeight()
			if i == 0 {
				table.AddRow(k, m.Subject, m.GetWeight())
			} else {
				table.AddRow("", m.Subject, m.Weight)
			}
		}
		table.AddRow("", "", fmt.Sprintf("sum=%d", wSum))
	}
	return table.Render()
}

type ScopedSkDescriber jwt.UserScope

func NewScopedSkDescriber(m *jwt.UserScope) *ScopedSkDescriber {
	return (*ScopedSkDescriber)(m)
}

func (s *ScopedSkDescriber) Describe() string {
	var buf bytes.Buffer
	buf.WriteString("\n")
	table := tablewriter.CreateTable()
	table.AddTitle("Scoped Signing Key - Details")
	table.AddRow("Key", s.Key)
	table.AddRow("role", s.Role)
	AddPermissions(table, s.Template.Permissions)
	AddLimits(table, s.Template.Limits)
	table.AddRow("Bearer Token", toYesNo(s.Template.BearerToken))
	if len(s.Template.AllowedConnectionTypes) > 0 {
		table.AddSeparator()
		AddListValues(table, "Allowed Connection Types", s.Template.AllowedConnectionTypes)
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
	local := i.GetTo()
	remote := string(i.Subject)

	if i.Type == jwt.Service && local != "" {
		local, remote = remote, local
	} else {
		local = string(i.LocalSubject)
	}

	if i.Token == "" {
		table.AddRow(i.Name, TitleCase(i.Type.String()), remote, local, "", Wide(i.Account), "Yes")
		return
	}
	expiration := ""
	ac, err := i.LoadActivation()
	if err != nil {
		expiration = fmt.Sprintf("error decoding: %v", err.Error())
	} else {
		expiration = RenderDate(ac.Expires)
	}
	table.AddRow(i.Name, TitleCase(i.Type.String()), remote, local, expiration, Wide(i.Account), "No")
}

func (i *ImportDescriber) IsRemoteImport() bool {
	return IsURL(i.Token)
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
	var tags jwt.TagList
	if ac, ok := claims.(*jwt.ActivationClaims); ok {
		if ac.IssuerAccount != "" {
			issuer = ac.IssuerAccount
		}
		tags = ac.Tags
	}
	if acc, ok := claims.(*jwt.ActivationClaims); ok {
		if acc.IssuerAccount != "" {
			issuer = acc.IssuerAccount
		}
		tags = acc.Tags
	}
	if uc, ok := claims.(*jwt.UserClaims); ok {
		label = "User ID"
		if uc.IssuerAccount != "" {
			issuer = uc.IssuerAccount
		}
		tags = uc.Tags
	}
	if oc, ok := claims.(*jwt.OperatorClaims); ok {
		label = "Operator ID"
		tags = oc.Tags
	}

	cd := claims.Claims()
	if cd.Name != "" {
		table.AddRow("Name", cd.Name)
	}
	table.AddRow(label, cd.Subject)
	table.AddRow("Issuer ID", cd.Issuer)
	if issuer != "" {
		table.AddRow("Issuer Account", issuer)
	}
	table.AddRow("Issued", RenderDate(cd.IssuedAt))
	table.AddRow("Expires", RenderDate(cd.Expires))
	if len(tags) > 0 {
		AddListValues(table, "Tags", tags)
	}
}

type ActivationDescriber struct {
	jwt.ActivationClaims
}

func NewActivationDescriber(a jwt.ActivationClaims) *ActivationDescriber {
	return &ActivationDescriber{ActivationClaims: a}
}

func (c *ActivationDescriber) Describe() string {
	hash, _ := c.HashID()

	table := tablewriter.CreateTable()
	table.AddTitle("Activation")
	AddStandardClaimInfo(table, &c.ActivationClaims)
	table.AddSeparator()
	table.AddRow("Hash ID", hash)
	table.AddSeparator()
	table.AddRow("Import Type", TitleCase(c.ImportType.String()))
	table.AddRow("Import Subject", string(c.ImportSubject))
	table.AddSeparator()

	return table.Render()
}

func AddLimits(table *tablewriter.Table, lim jwt.Limits) {
	if lim.Payload > 0 {
		v := fmt.Sprintf("%d bytes (≈%s)", lim.Payload, humanize.Bytes(uint64(lim.Payload)))
		table.AddRow("Max Msg Payload", v)
	} else {
		table.AddRow("Max Msg Payload", "Unlimited")
	}

	if lim.Data > 0 {
		v := fmt.Sprintf("%d bytes (≈%s)", lim.Data, humanize.Bytes(uint64(lim.Data)))
		table.AddRow("Max Data", v)
	} else {
		table.AddRow("Max Data", "Unlimited")
	}

	if lim.Subs > 0 {
		v := fmt.Sprintf("%d", lim.Subs)
		table.AddRow("Max Subs", v)
	} else {
		table.AddRow("Max Subs", "Unlimited")
	}

	if len(lim.Src) != 0 {
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

func AddListValues(table *tablewriter.Table, label string, values []string) {
	if len(values) > 0 {
		for i, v := range values {
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

func AddPermissions(table *tablewriter.Table, u jwt.Permissions) {
	if len(u.Pub.Allow) > 0 || len(u.Pub.Deny) > 0 ||
		len(u.Sub.Allow) > 0 || len(u.Sub.Deny) > 0 {
		table.AddSeparator()
		AddListValues(table, "Pub Allow", u.Pub.Allow)
		AddListValues(table, "Pub Deny", u.Pub.Deny)
		AddListValues(table, "Sub Allow", u.Sub.Allow)
		AddListValues(table, "Sub Deny", u.Sub.Deny)
	}
	if u.Resp == nil {
		table.AddRow("Response Permissions", "Not Set")
	} else {
		table.AddRow("Max Responses", u.Resp.MaxMsgs)
		table.AddRow("Response Permission TTL", u.Resp.Expires.String())
	}
}

func (u *UserDescriber) Describe() string {
	table := tablewriter.CreateTable()
	table.AddTitle("User")
	AddStandardClaimInfo(table, &u.UserClaims)
	if u.HasEmptyPermissions() {
		table.AddRow("Issuer Scoped", "Yes")
	} else {
		table.AddRow("Bearer Token", toYesNo(u.BearerToken))
		AddPermissions(table, u.Permissions)
		table.AddSeparator()
		AddLimits(table, u.Limits)

		if len(u.AllowedConnectionTypes) > 0 {
			table.AddSeparator()
			AddListValues(table, "Allowed Connection Types", u.AllowedConnectionTypes)
		}
	}
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
	table.AddTitle("Operator Details")
	AddStandardClaimInfo(table, &o.OperatorClaims)
	if o.AccountServerURL != "" {
		table.AddRow("Account JWT Server", o.AccountServerURL)
	}

	AddListValues(table, "Operator Service URLs", o.OperatorServiceURLs)

	if o.SystemAccount != "" {
		decoration := ""
		if fn, err := friendlyNames(o.Name); err == nil {
			if name, ok := fn[o.SystemAccount]; ok {
				decoration = " / " + name
			}
		}
		table.AddRow("System Account", o.SystemAccount+decoration)
	}
	table.AddRow("Require Signing Keys", o.StrictSigningKeyUsage)

	if len(o.SigningKeys) > 0 {
		table.AddSeparator()
		AddListValues(table, "Signing Keys", o.SigningKeys)
	}

	return table.Render()
}
