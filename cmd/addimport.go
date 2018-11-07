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
	"path/filepath"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddImportCmd() *cobra.Command {
	var params AddImportParams
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Add an import from a loaded activation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			cmd.Println("Success! - import added")
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.JTI, "jti", "j", "", "identify by jti")
	cmd.Flags().StringVarP(&params.subj, "subject", "s", "", "service or stream subject if activation contains multiple exports")
	cmd.Flags().StringVarP(&params.prefix, "prefix", "p", "", "subject prefix for stream imports")
	cmd.Flags().StringVarP(&params.to, "target-subject", "t", "", "service target subject")
	cmd.Flags().StringVarP(&params.Name, "name", "n", "", "name for the import")
	cmd.MarkFlagRequired("jti")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddImportCmd())
}

type AddImportParams struct {
	Import
	prefix string
	to     string
	subj   string
}

func (p *AddImportParams) Validate() error {
	if p.subj != "" {
		p.Subject = jwt.Subject(p.subj)
	}
	if p.Subject != "" {
		if err := p.Subject.Valid(); err != nil {
			return err
		}
	}

	s, err := getStore()
	if err != nil {
		return err
	}
	if !s.Has(filepath.Join(store.Activations, p.JTI+".jwt")) {
		return fmt.Errorf("JTI %q was not found", p.JTI)
	}

	d, err := s.Read(filepath.Join(store.Activations, p.JTI+".jwt"))
	ac, err := jwt.DecodeActivationClaims(string(d))
	if err != nil {
		return err
	}

	count := len(ac.Exports)
	if count == 0 {
		return errors.New("activation doesn't contain any services or streams")
	}

	if p.Subject == "" && count > 1 {
		return errors.New("activation contains multiple exports specify --subject to select one or --all to import all")
	}

	if p.Name == "" {
		p.Name = ac.Name
	}

	found := false
	if count == 1 && p.Subject == "" {
		if len(ac.Exports) == 1 {
			p.Subject = jwt.Subject(ac.Exports[0].Subject)
			if ac.Exports[0].IsStream() {
				p.Type = jwt.StreamType
			} else {
				p.Type = jwt.ServiceType
			}
			found = true
		}
	}

	if !found {
		for _, v := range ac.Exports {
			if jwt.Subject(v.Subject) == p.Subject {
				if v.IsStream() {
					p.Type = jwt.StreamType
					p.Map = jwt.Subject(p.prefix)
				} else {
					p.Type = jwt.ServiceType
					p.Map = jwt.Subject(p.to)
				}
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("subject %q was not found", p.Subject)
	}

	if p.prefix != "" && p.Type == jwt.ServiceType {
		return errors.New("services cannot have a prefix specified")
	}

	if p.to != "" && p.Type == jwt.StreamType {
		return errors.New("streams cannot have a target subject specified")
	}

	return nil
}

func (p *AddImportParams) Run() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	var i Imports
	s.ReadEntry(store.Imports, &i)

	if err := i.Add(&p.Import); err != nil {
		return err
	}

	return i.Store()
}
