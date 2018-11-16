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
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/dustin/go-humanize"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createDescribeAccountCmd() *cobra.Command {
	var params DescribeAccountParams
	cmd := &cobra.Command{
		Use:           "account",
		Short:         "Describes an account",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(cmd); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote account description to %q\n", params.outputFile)
			}
			return RunInterceptor(cmd)
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.accountName, "name", "n", "", "account name to describe")
	cmd.Flags().StringVarP(&params.file, "file", "f", "", "an account token file")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeAccountCmd())
}

type DescribeAccountParams struct {
	jwt.AccountClaims
	accountName string
	outputFile  string
	file        string
	token       string
}

func (p *DescribeAccountParams) Validate(cmd *cobra.Command) error {
	if p.accountName != "" && p.file != "" {
		cmd.SilenceUsage = false
		return errors.New("specify one of --name or --file")
	}

	var ac *jwt.AccountClaims
	if p.file != "" {
		d, err := ioutil.ReadFile(p.file)
		if err != nil {
			return fmt.Errorf("error reading %q: %v", p.file, err)
		}
		ac, err = jwt.DecodeAccountClaims(string(d))
		if err != nil {
			return fmt.Errorf("error decoding account claim %q: %v", p.file, err)
		}
	} else {
		s, err := GetStore()
		if err != nil {
			return err
		}

		ctx, err := s.GetContext()
		if err != nil {
			return err
		}

		if p.accountName == "" {
			p.accountName = ctx.Account.Name
		}

		if p.accountName == "" {
			// default cluster was not found by get context, so we either we have none or many
			cNames, err := s.ListSubContainers(store.Accounts)
			if err != nil {
				return err
			}
			c := len(cNames)
			if c == 0 {
				return errors.New("no accounts defined - add account first")
			} else {
				return errors.New("multiple accounts found - specify --account-name or navigate to an account directory")
			}
		}

		if !s.Has(store.Accounts, p.accountName, store.JwtName(p.accountName)) {
			return fmt.Errorf("account %q is not defined in the current context", p.accountName)
		}

		ac, err = s.ReadAccountClaim(p.accountName)
		if err != nil {
			return err
		}
	}
	if ac != nil {
		p.AccountClaims = *ac
	}
	return nil
}

func RenderLimits(table *tablewriter.Table, lim jwt.OperatorLimits) {
	if lim.Conn > 0 {
		table.AddRow("Max Active Connections", fmt.Sprintf("%d", lim.Conn))
	} else {
		table.AddRow("Max Active Connections", "Unlimited")
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

func (p *DescribeAccountParams) Run() error {
	buf := bytes.NewBuffer(nil)

	table := tablewriter.CreateTable()
	table.UTF8Box()

	table.AddTitle(fmt.Sprintf("Account %q Details", p.Name))
	table.AddRow("Subject", p.Subject)
	table.AddRow("Issuer", p.Issuer)
	table.AddRow("Issued", fmt.Sprintf("%s (%s)", UnixToDate(p.IssuedAt), HumanizedDate(p.IssuedAt)))

	if p.Expires > 0 {
		table.AddRow("Expires", fmt.Sprintf("%s (%s)", UnixToDate(p.Expires), HumanizedDate(p.Expires)))
	} else {
		table.AddRow("Expires", "No expiration")
	}

	RenderLimits(table, p.Limits)

	buf.WriteString(table.Render())

	serviceCount := 0
	for _, e := range p.Exports {
		if e.IsService() {
			serviceCount++
		}
	}
	streamCount := len(p.Exports) - serviceCount

	if serviceCount > 0 {
		exportedServices := tablewriter.CreateTable()
		exportedServices.AddTitle("Exported Services")
		exportedServices.AddHeaders("Name", "Subject")
		for _, e := range p.Exports {
			if e.IsService() {
				exportedServices.AddRow(e.Name, e.Subject)
			}
		}
		buf.WriteString(exportedServices.Render())
	} else {
		table := tablewriter.CreateTable()
		table.UTF8Box()
		table.AddTitle("Exported Services")
		table.AddRow("No services exported")
		buf.WriteString(table.Render())
	}

	if streamCount > 0 {
		exportedStreams := tablewriter.CreateTable()
		exportedStreams.AddTitle("Exported Streams")
		exportedStreams.AddHeaders("Name", "Subject")
		for _, e := range p.Exports {
			if e.IsStream() {
				exportedStreams.AddRow(e.Name, e.Subject)
			}
		}
		buf.WriteString(exportedStreams.Render())
	} else {
		table := tablewriter.CreateTable()
		table.UTF8Box()
		table.AddTitle("Exported Streams")
		table.AddRow("No streams exported")
		buf.WriteString(table.Render())
	}

	importedServiceCount := 0
	for _, e := range p.Imports {
		if e.IsService() {
			importedServiceCount++
		}
	}
	importedStreamCount := len(p.Imports) - importedServiceCount

	if importedServiceCount > 0 {
		et := tablewriter.CreateTable()
		et.AddTitle("Imported Services")
		et.AddHeaders("Name", "Subject", "Target", "Expires", "Target Account")
		for _, e := range p.Imports {
			if e.IsService() {
				if e.Token != "" {
					ic, err := jwt.DecodeActivationClaims(e.Token)
					if err != nil {
						return err
					}
					et.AddRow(e.Name, e.Subject, e.To, UnixToDate(ic.Expires), ic.Issuer)
				}
			}
		}
		buf.WriteString(et.Render())
	} else {
		table := tablewriter.CreateTable()
		table.UTF8Box()
		table.AddTitle("Imported Services")
		table.AddRow("No services imported")
		buf.WriteString(table.Render())
	}

	if importedStreamCount > 0 {
		et := tablewriter.CreateTable()
		et.AddTitle("Imported Streams")
		et.AddHeaders("Name", "Subject", "Prefix", "Expires", "Source Account")
		for _, e := range p.Imports {
			if e.IsStream() {
				ic, err := jwt.DecodeActivationClaims(e.Token)
				if err != nil {
					return err
				}
				et.AddRow(e.Name, e.Subject, e.To, UnixToDate(ic.Expires), ic.Issuer)
			}
		}
		buf.WriteString(et.Render())
	} else {
		table := tablewriter.CreateTable()
		table.UTF8Box()
		table.AddTitle("Imported Streams")
		table.AddRow("No streams imported")
		buf.WriteString(table.Render())
	}

	return Write(p.outputFile, buf.Bytes())
}
