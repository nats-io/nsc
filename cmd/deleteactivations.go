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
	"path"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteActivationCmd() *cobra.Command {
	var params DeleteActivationParams
	cmd := &cobra.Command{
		Use:   "activation",
		Short: "Deletes activations",
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
			cmd.Printf("Success! deleted %d activations\n", len(params.jtis))
			return nil
		},
	}

	deleteCmd.AddCommand(cmd)
	cmd.Flags().BoolVarP(&params.prompt, "interactive", "i", false, "prompt for activations")
	cmd.Flags().StringSliceVarP(&params.jtis, "jti", "j", nil, "jwt id identifying the activation - multiple ids can be specified by providing comma separated values or the option multiple times")

	return cmd
}

func init() {
	createDeleteActivationCmd()
}

type DeleteActivationParams struct {
	prompt bool
	jtis   []string
}

func (p *DeleteActivationParams) Validate() error {
	if p.jtis == nil && !p.prompt {
		return fmt.Errorf("error specify one of --jti or --interactive to specify the activation to delete")
	}
	return nil
}

func (p *DeleteActivationParams) Interact() error {
	if !p.prompt {
		return nil
	}
	if p.jtis == nil {
		sel, err := PickActivations()
		if err != nil {
			return err
		}
		for _, v := range sel {
			p.jtis = append(p.jtis, v.ID)
		}
	}

	ok, err := cli.PromptYN(fmt.Sprintf("Delete %d activation(s)", len(p.jtis)))
	if err != nil {
		return fmt.Errorf("error processing confirmation: %v", err)
	}

	if !ok {
		return errors.New("operation canceled")
	}

	return nil
}

func (p *DeleteActivationParams) Run() error {
	s, err := getStore()
	if err != nil {
		return err
	}

	for _, k := range p.jtis {
		if err := s.Delete(path.Join(store.Activations, k+".jwt")); err != nil {
			return err
		}
	}
	return nil
}

func PickActivations() ([]*jwt.ActivationClaims, error) {
	tokens, err := ListActivations()
	if err != nil {
		return nil, err
	}

	activations, err := ParseActivations(tokens)
	if err != nil {
		return nil, err
	}

	if len(activations) == 0 {
		return activations, nil
	}

	var labels = ActivationLabels(activations)

	idxs, err := cli.PromptMultipleChoices("Select activations", labels)
	if err != nil {
		return nil, err
	}

	var selection []*jwt.ActivationClaims
	for _, i := range idxs {
		selection = append(selection, activations[i])
	}
	return selection, nil
}
