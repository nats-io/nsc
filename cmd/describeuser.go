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

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createDescribeUserCmd() *cobra.Command {
	var params DescribeUserParams
	var cmd = &cobra.Command{
		Use:   "user",
		Short: "Describes an user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}
			if err := params.Interact(); err != nil {
				return err
			}
			if err := params.Run(); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote user description to %s\n", params.outputFile)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.prompt, "prompt", "i", false, "prompt for user")
	cmd.Flags().StringSliceVarP(&params.publicKeys, "public-key", "k", nil, "public key identifying the user")
	cmd.Flags().StringVarP(&params.match, "match", "m", "", "match key, name or tag")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeUserCmd())
}

type DescribeUserParams struct {
	publicKeys []string
	prompt     bool
	outputFile string
	match      string
}

func (p *DescribeUserParams) Validate() error {
	if p.prompt && p.match != "" {
		return fmt.Errorf("error specify one of --interactive or --match to select an user")
	}
	if p.match != "" {
		return nil
	}
	if p.publicKeys == nil && !p.prompt {
		return fmt.Errorf("error specify one of --public-key or --interactive to select an user")
	}
	return nil
}

func (p *DescribeUserParams) Interact() error {
	if !p.prompt && p.match == "" {
		return nil
	}
	if p.match != "" {
		users, err := ListUsers()
		if err != nil {
			return err
		}
		for _, v := range users {
			if v.Matches(p.match) {
				p.publicKeys = append(p.publicKeys, v.PublicKey)
			}
		}

		if len(p.publicKeys) == 0 {
			return fmt.Errorf("error %q didn't match anything", p.match)
		}
	}

	if p.publicKeys == nil {
		sel, err := PickUsers()
		if err != nil {
			return err
		}
		for _, v := range sel {
			p.publicKeys = append(p.publicKeys, v.PublicKey)
		}
	}
	return nil
}

func (p *DescribeUserParams) Run() error {
	buf := bytes.NewBuffer(nil)
	for i, v := range p.publicKeys {
		if i > 0 {
			buf.WriteByte('\n')
		}
		u := User{}
		u.PublicKey = v
		if err := u.Load(); err != nil {
			return err
		}
		buf.Write(u.Describe())

		table := tablewriter.CreateTable()
		table.AddTitle("User Activation Tokens")
		var tokens []*store.Token
		for _, id := range ngsStore.Index.Get(store.Tag{Key: "sub", Value: u.PublicKey}) {
			t, err := ngsStore.ReadToken(id)
			if err != nil {
				return err
			}
			tokens = append(tokens, t)
		}
		if len(tokens) == 0 {
			table.AddRow("User has no activations")
		} else {
			table.AddHeaders("Name", "ID", "Issued", "Expires")
			for _, t := range tokens {
				table.AddRow(t.Name, t.ID, UnixToDate(t.IssuedAt), UnixToDate(t.Expires))
			}
		}
		buf.WriteString(table.Render())
	}
	return Write(p.outputFile, buf.Bytes())
}
