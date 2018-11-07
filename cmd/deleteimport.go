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

func createDeleteImportCmd() *cobra.Command {
	var params DeleteImportParams
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Deletes imports",
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
			cmd.Printf("Success! - deleted %d imports\n", len(params.selection))
			return nil
		},
	}

	deleteCmd.AddCommand(cmd)
	cmd.Flags().BoolVarP(&params.prompt, "interactive", "i", false, "prompt for imports")
	cmd.Flags().StringSliceVarP(&params.subjects, "subject", "", nil, "subject(s) identifying the stream or service")

	return cmd
}

func init() {
	createDeleteImportCmd()
}

type DeleteImportParams struct {
	prompt    bool
	subjects  []string
	selection Imports
}

func (p *DeleteImportParams) Validate() error {
	//FIXME: ambigous selection without JTI
	if p.prompt && p.subjects != nil {
		return fmt.Errorf("error specify one of --subject, or --interactive to specify the import to delete")
	}
	if p.subjects == nil && !p.prompt {
		return fmt.Errorf("error specify one of --subject or --interactive to specify the import to delete")
	}

	return nil
}

func (p *DeleteImportParams) Interact() error {
	if !p.prompt {
		return nil
	}
	if p.subjects == nil {
		var err error
		p.selection, err = PickImports()
		if err != nil {
			return err
		}
	}

	ok, err := cli.PromptYN(fmt.Sprintf("Delete %d export(s)", len(p.selection)))
	if err != nil {
		return fmt.Errorf("error processing confirmation: %v", err)
	}

	if !ok {
		return errors.New("operation canceled")
	}

	return nil
}

func (p *DeleteImportParams) Run() error {
	var imports Imports
	if err := imports.Load(); err != nil {
		return err
	}

	for _, k := range p.selection {
		imports.Remove(k)
	}
	return imports.Store()
}

func PickImports() (Imports, error) {
	var imports Imports
	if err := imports.Load(); err != nil {
		return nil, err
	}

	if len(imports) == 0 {
		return imports, nil
	}

	var labels []string
	for _, ae := range imports {
		labels = append(labels, ae.String())
	}

	idxs, err := cli.PromptMultipleChoices("Select imports", labels)
	if err != nil {
		return nil, err
	}

	var selection []*Import
	for _, i := range idxs {
		selection = append(selection, imports[i])
	}
	return selection, nil
}
