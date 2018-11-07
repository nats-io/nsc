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
	"io/ioutil"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createDescribeAccountCmd() *cobra.Command {
	var params DescribeAccountParams
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Describes the current account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote account description to %q\n", params.outputFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.file, "file", "f", "", "an account token file - if not specified, the current account is described")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeAccountCmd())
}

type DescribeAccountParams struct {
	outputFile string
	file       string
	token      string
}

func (p *DescribeAccountParams) Validate() error {
	var err error
	if p.file == "" {
		p.token, err = GenerateAccountJWT("")
		if err != nil {
			return err
		}
	}
	if p.file != "" {
		d, err := ioutil.ReadFile(p.file)
		if err != nil {
			return err
		}
		p.token = ExtractToken(string(d))
	}
	return nil
}

func (p *DescribeAccountParams) Run() error {
	c, err := jwt.DecodeAccountClaims(p.token)
	if err != nil {
		return fmt.Errorf("error decoding token: %v", err)
	}

	buf := bytes.NewBuffer(nil)

	table := tablewriter.CreateTable()
	table.AddTitle("Account Details")
	table.AddRow("Subject", c.Subject)
	table.AddRow("Issuer", c.Issuer)
	if c.Expires > 0 {
		table.AddRow("Expires", UnixToDate(c.Expires))
	}
	table.UTF8Box()
	buf.WriteString(table.Render())

	if c.Access != "" {
		t := tablewriter.CreateTable()
		t.AddTitle("Access Token")
		ac, err := jwt.DecodeActivationClaims(c.Access)
		if err != nil {
			return err
		}
		t.AddRow("Issuer", ac.Issuer)
		if ac.Expires > 0 {
			t.AddRow("Expires", UnixToDate(ac.Expires))
		}
		buf.WriteString(t.Render())

		if len(ac.Exports) > 0 {
			et := tablewriter.CreateTable()
			et.AddTitle("Exports")
			et.AddHeaders("Name", "Type", "Subject")
			for _, e := range ac.Exports {
				et.AddRow(e.Name, e.Type, e.Subject)
			}
			buf.WriteString(et.Render())
		}
	}

	serviceCount := 0
	for _, e := range c.Exports {
		if e.IsService() {
			serviceCount++
		}
	}
	streamCount := len(c.Exports) - serviceCount

	if serviceCount > 0 {
		et := tablewriter.CreateTable()
		et.AddTitle("Exported Services")
		et.AddHeaders("Name", "Subject")
		for _, e := range c.Exports {
			if e.IsService() {
				et.AddRow(e.Name, e.Subject)
			}
		}
		buf.WriteString(et.Render())
	}

	if streamCount > 0 {
		et := tablewriter.CreateTable()
		et.AddTitle("Exported Streams")
		et.AddHeaders("Name", "Subject")
		for _, e := range c.Exports {
			if e.IsStream() {
				et.AddRow(e.Name, e.Subject)
			}
		}
		buf.WriteString(et.Render())
	}

	if len(c.Imports) > 0 {
		importedServiceCount := 0
		for _, e := range c.Imports {
			if e.IsService() {
				importedServiceCount++
			}
		}
		importedStreamCount := len(c.Imports) - importedServiceCount

		if importedServiceCount > 0 {
			et := tablewriter.CreateTable()
			et.AddTitle("Imported Services")
			et.AddHeaders("Name", "Subject", "Target", "Expires", "Target Account")
			for _, e := range c.Imports {
				if e.IsService() {
					ic, err := jwt.DecodeActivationClaims(e.Auth)
					if err != nil {
						return err
					}
					et.AddRow(e.Name, e.Subject, e.To, UnixToDate(ic.Expires), ic.Issuer)
				}
			}
			buf.WriteString(et.Render())
		}

		if importedStreamCount > 0 {
			et := tablewriter.CreateTable()
			et.AddTitle("Imported Streams")
			et.AddHeaders("Name", "Subject", "Prefix", "Expires", "Source Account")
			for _, e := range c.Imports {
				if e.IsStream() {
					ic, err := jwt.DecodeActivationClaims(e.Auth)
					if err != nil {
						return err
					}
					et.AddRow(e.Name, e.Subject, e.Prefix, UnixToDate(ic.Expires), ic.Issuer)
				}
			}
			buf.WriteString(et.Render())
		}
	}

	table = tablewriter.CreateTable()
	table.AddTitle("Account JWT History")
	var tokens []*store.Token
	for _, id := range ngsStore.Index.Intersect(store.Tag{Key: "sub", Value: c.Issuer},
		store.Tag{Key: "iss", Value: c.Issuer}) {
		t, err := ngsStore.ReadToken(id)
		if err != nil {
			return err
		}
		tokens = append(tokens, t)
	}
	if len(tokens) == 0 {
		table.AddRow("Account has no issued JWTs")
	} else {
		table.AddHeaders("Name", "ID", "Issued", "Expires")
		for _, t := range tokens {
			table.AddRow(t.Name, t.ID, UnixToDate(t.IssuedAt), UnixToDate(t.Expires))
		}
	}
	buf.WriteString(table.Render())

	return Write(p.outputFile, buf.Bytes())
}
