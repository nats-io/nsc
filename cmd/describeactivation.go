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
	"strings"

	"github.com/nats-io/jwt"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createDescribeActivationCmd() *cobra.Command {
	var params DescribeActivationParams
	var cmd = &cobra.Command{
		Use:   "activation",
		Short: "Describes an activation",
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
				cmd.Printf("Success! wrote activation description to %s\n", params.outputFile)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.prompt, "prompt", "i", false, "prompt for activation")
	cmd.Flags().StringSliceVarP(&params.jti, "jti", "j", nil, "jti identifying the activation")
	cmd.Flags().StringVarP(&params.match, "match", "m", "", "match jti, name or subject")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeActivationCmd())
}

type DescribeActivationParams struct {
	jti        []string
	prompt     bool
	outputFile string
	match      string
}

func (p *DescribeActivationParams) Validate() error {
	if p.prompt && p.match != "" {
		return fmt.Errorf("error specify one of --interactive or --match to select an activation")
	}
	if p.match != "" {
		return nil
	}
	if p.jti == nil && !p.prompt {
		return fmt.Errorf("error specify one of --jti or --interactive to select an activation")
	}
	return nil
}

func (p *DescribeActivationParams) Interact() error {
	if !p.prompt && p.match == "" {
		return nil
	}
	if p.match != "" {
		activations, err := ListActivations()
		if err != nil {
			return err
		}
		for _, v := range activations {
			ac, err := jwt.DecodeActivationClaims(v)
			if err != nil {
				return fmt.Errorf("error decoding activation: %v", err)
			}
			if strings.Contains(ac.ID, p.match) {
				p.jti = append(p.jti, ac.ID)
			}
			if strings.Contains(ac.Name, p.match) {
				p.jti = append(p.jti, ac.ID)
			}
			for _, s := range ac.Exports {
				if strings.Contains(s.Name, p.match) {
					p.jti = append(p.jti, ac.ID)
					continue
				}
				if strings.Contains(string(s.Subject), p.match) {
					p.jti = append(p.jti, ac.ID)
					continue
				}
			}
		}

		if len(p.jti) == 0 {
			return fmt.Errorf("error %q didn't match anything", p.match)
		}
	}

	if p.jti == nil {
		sel, err := PickActivations()
		if err != nil {
			return err
		}
		for _, v := range sel {
			p.jti = append(p.jti, v.ID)
		}
	}
	return nil
}

func (p *DescribeActivationParams) Run() error {
	buf := bytes.NewBuffer(nil)
	for i, v := range p.jti {
		if i > 0 {
			buf.WriteString("\n")
		}
		c, err := LoadActivation(v)
		if err != nil {
			return err
		}

		table := tablewriter.CreateTable()
		table.UTF8Box()
		table.AddTitle(fmt.Sprintf("Activation %s", c.ID))
		table.AddRow("Name:", DefaultName(c.Name))
		table.AddRow("Issuer:", DefaultName(c.Issuer))
		table.AddRow("Expires:", UnixToDate(c.Expires))
		buf.WriteString(table.Render())
		buf.WriteString("\n")

		serviceCount := 0
		for _, e := range c.Exports {
			if e.IsService() {
				serviceCount++
			}
		}
		streamCount := len(c.Exports) - serviceCount

		if serviceCount > 0 {
			et := tablewriter.CreateTable()
			et.AddTitle("Services")
			et.AddHeaders("Name", "Subject")
			for _, e := range c.Exports {
				if e.IsService() {
					et.AddRow(e.Name, e.Subject)
				}
			}
			buf.WriteString(et.Render())
			buf.WriteString("\n")
		}

		if streamCount > 0 {
			et := tablewriter.CreateTable()
			et.AddTitle("Streams")
			et.AddHeaders("Name", "Subject")
			for _, e := range c.Exports {
				if e.IsStream() {
					et.AddRow(e.Name, e.Subject)
				}
			}
			buf.WriteString(et.Render())
			buf.WriteString("\n")
		}
	}

	return Write(p.outputFile, buf.Bytes())
}
