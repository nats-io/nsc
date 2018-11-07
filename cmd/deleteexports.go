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
	"errors"
	"fmt"

	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createDeleteExportsCmd() *cobra.Command {
	var params DeleteExportParams
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Deletes exports",
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
			cmd.Printf("Success! - deleted %d exports\n", len(params.subjects))
			return nil
		},
	}

	deleteCmd.AddCommand(cmd)
	cmd.Flags().BoolVarP(&params.prompt, "interactive", "i", false, "prompt for exports")
	cmd.Flags().StringSliceVarP(&params.subjects, "subject", "", nil, "subject(s) identifying the stream or service")

	return cmd
}

func init() {
	createDeleteExportsCmd()
}

type DeleteExportParams struct {
	prompt   bool
	subjects []string
}

func (p *DeleteExportParams) Validate() error {
	if p.prompt && p.subjects != nil {
		return fmt.Errorf("error specify one of --subject, or --interactive to specify the export to delete")
	}
	if p.subjects == nil && !p.prompt {
		return fmt.Errorf("error specify one of --subject or --interactive to specify the export to delete")
	}
	return nil
}

func (p *DeleteExportParams) Interact() error {
	if !p.prompt {
		return nil
	}
	if p.subjects == nil {
		sel, err := PickExports()
		if err != nil {
			return err
		}
		for _, v := range sel {
			p.subjects = append(p.subjects, string(v.Subject))
		}
	}

	ok, err := cli.PromptYN(fmt.Sprintf("Delete %d export(s)", len(p.subjects)))
	if err != nil {
		return fmt.Errorf("error processing confirmation: %v", err)
	}

	if !ok {
		return errors.New("operation canceled")
	}

	return nil
}

func (p *DeleteExportParams) Run() error {
	var exports Exports
	if err := exports.Load(); err != nil {
		return err
	}

	for _, k := range p.subjects {
		exports.Remove(NewServiceExport("", k))
	}
	return exports.Store()
}

func PickExports() ([]*Export, error) {
	var exports Exports
	if err := exports.Load(); err != nil {
		return nil, err
	}

	if len(exports) == 0 {
		return exports, nil
	}

	var labels []string
	for _, ae := range exports {
		labels = append(labels, ae.String())
	}

	idxs, err := cli.PromptMultipleChoices("Select exports", labels)
	if err != nil {
		return nil, err
	}

	var selection []*Export
	for _, i := range idxs {
		selection = append(selection, exports[i])
	}
	return selection, nil
}
