/*
 * Copyright 2020-2025 The NATS Authors
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
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

var accDetail bool
var outputFile string
var users, showKeys, detail bool

func createDiagramCmd() *cobra.Command {
	diagram := &cobra.Command{
		Use:          "diagram",
		Short:        "Generate diagrams for this store",
		Args:         MaxArgs(0),
		SilenceUsage: true,
	}
	return diagram
}

func createComponentDiagreamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "component",
		Short:        "Generate a plantuml component diagram for this store",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate diagram component`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return componentDiagram(cmd, accDetail)
		},
	}
	cmd.Flags().BoolVarP(&accDetail, "detail", "", false, "Include account descriptions")
	cmd.Flags().StringVarP(&outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	return cmd
}

func createObjectDiagramCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "object",
		Short:        "Generate a plantuml object diagram for this store",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate diagram object`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return objectDiagram(cmd, users, showKeys, detail)
		},
	}

	cmd.Flags().BoolVarP(&showKeys, "show-keys", "", false, "Include keys in diagram")
	cmd.Flags().BoolVarP(&users, "users", "", false, "Include User")
	cmd.Flags().BoolVarP(&detail, "detail", "", false, "Include empty/unlimited values")
	cmd.Flags().StringVarP(&outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	return cmd
}

func init() {
	diagram := createDiagramCmd()
	generateCmd.AddCommand(diagram)
	diagram.AddCommand(createComponentDiagreamCmd())
	diagram.AddCommand(createObjectDiagramCmd())
}

const rename = "<&resize-width>"

func accessMod(e *jwt.Export) string {
	if e.TokenReq {
		return "private"
	}
	return "public"
}

func expType(e *jwt.Export) string {
	switch e.Type {
	case jwt.Stream:
		return "stream"
	case jwt.Service:
		return "service"
	default:
		return "n/a"
	}
}

func expName(e *jwt.Export) string {
	name := e.Name
	if name == "" {
		name = string(e.Subject)
	}
	return name
}

func expId(subject string, e *jwt.Export) string {
	s := strings.ReplaceAll(expName(e), " ", "_")
	s = strings.ReplaceAll(s, "*", "_A_")
	s = strings.ReplaceAll(s, ">", "_G_")
	s = strings.ReplaceAll(s, "$", "_D_")
	s = strings.ReplaceAll(s, "-", "_M_")
	return fmt.Sprintf("%s_%s", subject, s)
}

func impSubj(i *jwt.Import) (local string, remote string) {
	if i.LocalSubject != "" {
		local = string(i.LocalSubject)
		remote = string(i.Subject)
	} else {
		local = i.GetTo()
		if local == "" {
			local = string(i.Subject)
		}
		remote = string(i.Subject)
		if i.Type == jwt.Service {
			local, remote = remote, local
		}
	}
	return
}

func componentDiagram(cmd *cobra.Command, accDetail bool) error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	op, err := s.ReadOperatorClaim()
	if err != nil {
		return err
	}
	var b bytes.Buffer
	f := bufio.NewWriter(&b)
	bldrPrntf := func(format string, args ...interface{}) {
		fmt.Fprintln(f, fmt.Sprintf(format, args...))
	}
	addNote := func(ref string, i jwt.Info) {
		if !accDetail {
			return
		}
		if i.Description != "" || i.InfoURL != "" {
			link := ""
			if i.InfoURL != "" {
				link = fmt.Sprintf("\n[[%s info]]", i.InfoURL)
			}
			bldrPrntf("note right of %s\n%s %s\nend note", ref, cli.WrapString(20, i.Description), link)
		}
	}
	bldrPrntf(`@startuml
skinparam component {
	ArrowFontName Arial
	ArrowFontColor #636363
    ArrowSize 10pt
}
skinparam interface {
    backgroundColor<<not-found public service>> Red
    backgroundColor<<not-found private service>> Red
    backgroundColor<<not-found public stream>> Red
    backgroundColor<<not-found private stream>> Red
}
`)
	addValidationNote := func(id string, name string, vr *jwt.ValidationResults) {
		if len(vr.Issues) == 0 {
			return
		}
		if len(vr.Issues) == 1 && strings.HasPrefix(vr.Issues[0].Description, "the field to has been deprecated") {
			return
		}
		bldrPrntf("note left of %s\n", id)
		bldrPrntf("** Validation Issues by %s**\n", name)
		for _, v := range vr.Issues {
			if !strings.HasPrefix(v.Description, "the field to has been deprecated") {
				bldrPrntf("* %s\n", v.Description)
			}
		}
		bldrPrntf("end note")
	}
	escapeSubjectLabel := func(sub string) string {
		// * is special notation in plantuml. (escape by adding a space)
		if strings.HasPrefix(sub, "*") {
			return fmt.Sprintf(" %s", sub)
		}
		return sub
	}
	bldrPrntf(`title Component Diagram of Accounts - Operator %s`, op.Name)
	accs, _ := s.ListSubContainers(store.Accounts)
	accBySubj := make(map[string]*jwt.AccountClaims)
	for _, accName := range accs {
		ac, err := s.ReadAccountClaim(accName)
		if err != nil {
			return err
		}
		accBySubj[ac.Subject] = ac
		if len(ac.Imports)+len(ac.Exports) == 0 {
			continue
		}
		bldrPrntf(`component [%s] as %s <<account>>`, ac.Name, ac.Subject)
		addNote(ac.Subject, ac.Info)
		for _, e := range ac.Exports {
			eId := expId(ac.Subject, e)
			bldrPrntf(`interface "%s" << %s %s >> as %s`, expName(e), accessMod(e), expType(e), eId)
			bldrPrntf(`%s -- %s : ""%s"""`, expId(ac.Subject, e), ac.Subject, escapeSubjectLabel(string(e.Subject)))
			addNote(eId, e.Info)

			vr := jwt.ValidationResults{}
			e.Validate(&vr)
			addValidationNote(eId, ac.Name, &vr)
		}
		bldrPrntf("")
	}
	for _, accSubj := range accs {
		ac, err := s.ReadAccountClaim(accSubj)
		if err != nil {
			return err
		}
		for _, i := range ac.Imports {
			local, remote := impSubj(i)
			foundExport := false
			tokenReq := false
			if i.Token != "" {
				tokenReq = true
			}
			matchingExport := &jwt.Export{Subject: jwt.Subject(remote), Type: i.Type, TokenReq: tokenReq} // dummy
			impAcc, foundExporter := accBySubj[i.Account]
			if foundExporter {
				for _, e := range impAcc.Exports {
					if i.Type == e.Type && jwt.Subject(remote).IsContainedIn(e.Subject) {
						matchingExport = e
						foundExport = true
						break
					}
				}
			}
			id := expId(i.Account, matchingExport)
			if !foundExport {
				bldrPrntf(`interface " " << not-found %s %s >> as %s`, accessMod(matchingExport), expType(matchingExport), id)
			}
			if local != remote {
				bldrPrntf(`%s "%s%s" ..> %s : "%s"`, ac.Subject, rename, local, id, escapeSubjectLabel(remote))
			} else {
				bldrPrntf(`%s ..> %s : "%s"`, ac.Subject, id, escapeSubjectLabel(remote))
			}
			vr := jwt.ValidationResults{}
			i.Validate(ac.Subject, &vr)
			if matchingExport.TokenReq && i.Token == "" {
				vr.AddError("Export is private but no activation token")
			} else if !matchingExport.TokenReq && i.Token != "" {
				vr.AddError("Export is public but import has activation token")
			}
			if !foundExporter {
				vr.AddError("Exporting account not present: %s", i.Account)
			}
			addValidationNote(id, ac.Name, &vr)
		}
	}
	bldrPrntf("legend\n\"%sX\", the imported subject is rewritten to X\nend legend", rename)
	bldrPrntf(`footer generated by nsc - store dir: %s - date: %s `, s.Dir, time.Now().Format("2006-01-02 15:04:05"))
	bldrPrntf("@enduml")

	_ = f.Flush()
	if IsStdOut(outputFile) {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), b.String()); err != nil {
			return err
		}
	} else {
		return WriteFile(outputFile, b.Bytes())
	}
	return nil
}

func objectDiagram(cmd *cobra.Command, users bool, showKeys bool, detail bool) error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}
	op, err := s.ReadOperatorClaim()
	if err != nil {
		return err
	}
	var b bytes.Buffer
	f := bufio.NewWriter(&b)

	bldrPrntf := func(format string, args ...interface{}) {
		_, err := fmt.Fprintln(f, fmt.Sprintf(format, args...))
		if err != nil {
			panic(err)
		}
	}
	addNote := func(ref string, i jwt.Info) {
		if i.Description != "" || i.InfoURL != "" {
			link := ""
			if i.InfoURL != "" {
				link = fmt.Sprintf("\n[[%s info]]", i.InfoURL)
			}
			bldrPrntf("note right of %s\n%s %s\nend note", ref, cli.WrapString(20, i.Description), link)
		}
	}
	addValue := func(name string, format string, args ...interface{}) {
		value := fmt.Sprintf(format, args...)
		if value != "" || detail {
			bldrPrntf(`%s = %s`, name, value)
		}
	}
	addList := func(name string, list []string) {
		if len(list) != 0 || detail {
			addValue(name, strings.Trim(fmt.Sprintf("%q", list), " []"))
		}
	}
	addTime := func(name string, when int64) {
		if when != 0 {
			bldrPrntf(`%s = %s`, name, time.Unix(when, 0).Format("2006-01-02 15:04:05"))
		} else if detail {
			bldrPrntf(`%s = not set`, name)
		}
	}
	addClaims := func(data jwt.ClaimsData, tags jwt.TagList) {
		if showKeys {
			addValue("Identity Key", data.Subject)
			addValue("Identity Key Present", fmt.Sprintf("%t", ctx.KeyStore.HasPrivateKey(data.Subject)))
		}
		addList("Tags", tags)
		addTime("Issued At", data.IssuedAt)
		addTime("Valid From", data.NotBefore)
		addTime("Expires", data.Expires)
	}
	addValidationResults := func(claims jwt.Claims) {
		vr := jwt.ValidationResults{}
		claims.Validate(&vr)
		if len(vr.Issues) == 0 {
			if !detail {
				return
			}
			bldrPrntf("--- Validation (no issues) ---")
		} else {
			bldrPrntf("==**<color:red>Validation</color>**==")
		}
		addValue("Errors", strings.Trim(fmt.Sprintf("%q", vr.Errors()), " []"))
		addList("Warnings", vr.Warnings())
	}
	addLimit := func(name string, limit int64) {
		if limit == -1 {
			addValue(name, "-1 (unlimited)")
		} else if limit == 0 {
			addValue(name, "0 (disabled)")
		} else {
			addValue(name, fmt.Sprintf("%d", limit))
		}
	}
	addAccLimits := func(l jwt.AccountLimits) {
		if l.IsUnlimited() {
			if !detail {
				return
			}
			bldrPrntf("--- Account Limits (unlimited)---")
		} else {
			bldrPrntf("--- Account Limits ---")
		}
		addLimit("Max Exports", l.Exports)
		addLimit("Max Imports", l.Imports)
		addLimit("Max Client Connections", l.Conn)
		addLimit("Max Leaf Node Connections", l.LeafNodeConn)
		addValue("Allow Wildcard Exports", fmt.Sprintf("%t", l.WildcardExports))
		addValue("Disallow bearer token", fmt.Sprintf("%t", l.DisallowBearer))
	}
	addNatsLimits := func(l jwt.NatsLimits) {
		if l.IsUnlimited() {
			if !detail {
				return
			}
			bldrPrntf("--- Nats Limits (unlimited)---")
		} else {
			bldrPrntf("--- Nats Limits ---")
		}
		addLimit("Max Payload", l.Payload)
		addLimit("Max Subscriber", l.Subs)
		addLimit("Max Number of bytes", l.Data)
	}
	addJSLimits := func(l jwt.JetStreamLimits) {
		if l.IsUnlimited() {
			bldrPrntf("--- Jetstream Limits (unlimited) ---")
		} else if l.DiskStorage == 0 && l.MemoryStorage == 0 {
			if !detail {
				return
			}
			bldrPrntf("--- Jetstream Limits (disabled) ---")
		} else {
			bldrPrntf("--- Jetstream Limits ---")
		}
		addLimit("Max Memory Storage", l.MemoryStorage)
		addLimit("Max Disk Storage", l.DiskStorage)
		addLimit("Max Streams", l.Streams)
		addLimit("Max Consumer", l.Consumer)
	}
	addUserLimits := func(l jwt.UserLimits) {
		if l.IsUnlimited() {
			if !detail {
				return
			}
			bldrPrntf("--- User Limits (unlimited)---")
		} else {
			bldrPrntf("--- User Limits ---")
		}
		addList("Permitted CIDR blocks", l.Src)

		bldr := strings.Builder{}
		for _, t := range l.Times {
			bldr.WriteString(fmt.Sprintf(" [%s-%s]", t.Start, t.End))
		}
		addValue("Permitted Times to Connect", l.Locale+bldr.String())
	}
	addSigningKeys := func(subject string, subjName string, permissionsType string, keys jwt.StringList) {
		if !showKeys {
			return
		}
		if len(keys) == 0 {
			return
		}
		permId := fmt.Sprintf("%s_sk", subject)
		if permissionsType != "" {
			permissionsType += " "
		}
		bldrPrntf(`map "%s" as %s << %ssigning keys >> {`, subjName, permId, permissionsType)
		bldrPrntf(`key => stored`)
		for _, k := range keys {
			bldrPrntf(`%s => %t`, k, ctx.KeyStore.HasPrivateKey(k))
		}
		bldrPrntf(`}`)
		bldrPrntf(`%s *-- %s `, subject, permId)
	}
	permissionsSet := func(p jwt.Permissions) bool {
		return !(len(p.Pub.Allow)+len(p.Pub.Deny)+len(p.Sub.Allow)+len(p.Sub.Deny) == 0 && p.Resp == nil)
	}
	addPermissions := func(subject string, subjName string, permissionsType string, p jwt.Permissions) string {
		addSubjects := func(name string, list jwt.StringList) {
			if len(list) == 0 && !detail {
				return
			}
			bldrPrntf("--- %s ---", name)
			for _, sub := range list {
				bldrPrntf(` ""%s""`, sub)
			}
		}
		permId := fmt.Sprintf("%s_permissions", subject)
		if permissionsType != "" {
			permissionsType += " "
		}
		bldrPrntf(`object "%s" as %s << %spermissions >> {`, subjName, permId, permissionsType)
		addSubjects("Publish Deny", p.Pub.Deny)
		addSubjects("Publish Allow", p.Pub.Allow)
		addSubjects("Subscribe Deny", p.Sub.Deny)
		addSubjects("Subscribe Allow", p.Sub.Allow)
		if p.Resp == nil {
			if detail {
				bldrPrntf("--- Response Permissions (server default)---")
			}
		} else {
			bldrPrntf("--- Response Permissions ---")
			addValue("Expiration", p.Resp.Expires.String())
			addLimit("Max Messages", int64(p.Resp.MaxMsgs))
		}
		bldrPrntf(`}`)
		return permId
	}
	connectSigned := func(signer jwt.ClaimsData, signee jwt.ClaimsData) {
		if signee.Issuer == signee.Subject {
			bldrPrntf(`%s -- %s : "self signed >"`, signee.Issuer, signee.Subject)
		} else if !showKeys {
			bldrPrntf(`%s -- %s : "signed >"`, signer.Subject, signee.Subject)
		} else if signee.Issuer == signer.Subject {
			bldrPrntf(`%s -- %s : "signed >"`, signee.Issuer, signee.Subject)
		} else {
			bldrPrntf(`%s_sk::%s -- %s : "signed >"`, signer.Subject, signee.Issuer, signee.Subject)
		}
	}
	bldrPrntf(`@startuml`)
	bldrPrntf(`title Object Diagram`)
	bldrPrntf(`object "%s" as %s << operator >> {`, op.Name, op.Subject)
	addClaims(op.ClaimsData, op.Tags)
	addValue("JWT Version", "%d", op.Version)
	addValue("account server", op.AccountServerURL)
	addValue("Strict signing key usage", "%t", op.StrictSigningKeyUsage)
	addValidationResults(op)
	bldrPrntf("}")

	addSigningKeys(op.Subject, op.Name, "operator", op.SigningKeys)

	accs, _ := s.ListSubContainers(store.Accounts)
	for _, accName := range accs {
		ac, err := s.ReadAccountClaim(accName)
		if err != nil {
			return err
		}
		tp := "account"
		if ac.Subject == op.SystemAccount {
			tp = "system account"
		}
		bldrPrntf(`object "%s" as %s << %s >> {`, ac.Name, ac.Subject, tp)
		addClaims(ac.ClaimsData, ac.Tags)

		addAccLimits(ac.Limits.AccountLimits)
		addNatsLimits(ac.Limits.NatsLimits)
		addJSLimits(ac.Limits.JetStreamLimits)
		addValidationResults(ac)
		bldrPrntf("}")

		defPermId := ""
		if permissionsSet(ac.DefaultPermissions) {
			defPermId = addPermissions(ac.Subject, ac.Name, "default", ac.DefaultPermissions)
			bldrPrntf(`%s *-- %s`, ac.Subject, defPermId)
		}
		addSigningKeys(ac.Subject, ac.Name, "account", ac.SigningKeys.Keys())

		connectSigned(op.ClaimsData, ac.ClaimsData)
		addNote(ac.Subject, ac.Info)
		if !users {
			continue
		}
		usrs, _ := s.ListEntries(store.Accounts, accName, store.Users)
		for _, usrName := range usrs {
			uc, err := s.ReadUserClaim(accName, usrName)
			if err != nil {
				return err
			}
			bldrPrntf(`object "%s" as %s << user >> {`, uc.Name, uc.Subject)
			addClaims(uc.ClaimsData, uc.Tags)
			addValue("Bearer Token", fmt.Sprintf("%t", uc.BearerToken))
			addList("Allowed Connection Types", uc.AllowedConnectionTypes)
			addNatsLimits(uc.NatsLimits)
			addUserLimits(uc.UserLimits)
			addValidationResults(uc)
			bldrPrntf("}")

			if permissionsSet(uc.Permissions) {
				permId := addPermissions(uc.Subject, uc.Name, "user", uc.Permissions)
				bldrPrntf(`%s *-- %s : "API restricted by >"`, uc.Subject, permId)
			} else if defPermId != "" {
				bldrPrntf(`%s -- %s : "API restricted by >"`, uc.Subject, defPermId)
			}
			connectSigned(ac.ClaimsData, uc.ClaimsData)
		}
	}
	bldrPrntf(`footer generated by nsc - store dir: %s - date: %s `, s.Dir, time.Now().Format("2006-01-02 15:04:05"))
	bldrPrntf("@enduml")
	_ = f.Flush()

	if !IsStdOut(outputFile) {
		return WriteFile(outputFile, b.Bytes())
	} else {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), b.String())
		return err
	}
}
