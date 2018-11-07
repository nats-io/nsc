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

	"github.com/spf13/cobra"
)

func createAddExportCmd() *cobra.Command {
	var params AddExportParams
	var cmd = &cobra.Command{
		Use:   "export",
		Short: "Add a publicly exported service or stream",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}
			if err := params.Run(); err != nil {
				return err
			}

			n := "stream"
			if params.service != "" {
				n = "service"
			}
			cmd.Printf("Success! - added %s %s\n", n, params.name)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.service, "service", "", "", "subject where the service can receive requests")
	cmd.Flags().StringVarP(&params.stream, "stream", "", "", "subject or wildcard subject where messages are published")
	cmd.Flags().StringVarP(&params.name, "name", "", "", "name for the service or stream")
	cmd.Flags().StringSliceVarP(&params.tag, "tag", "", nil, "tag for the service or stream")
	cmd.MarkFlagRequired("name")
	return cmd
}

func init() {
	addCmd.AddCommand(createAddExportCmd())
}

type AddExportParams struct {
	service string
	stream  string
	name    string
	tag     []string
}

func (p *AddExportParams) Validate() error {
	if p.stream == "" && p.service == "" {
		return errors.New("specify one of --stream or --service")
	}
	if p.stream != "" && p.service != "" {
		return errors.New("specify only one of --stream or --service")
	}
	return nil
}

func (p *AddExportParams) Run() error {
	_, err := getStore()
	if err != nil {
		return err
	}

	var exports Exports
	if err := exports.Load(); err != nil {
		return err
	}

	if p.service != "" {
		if err := exports.Add(NewServiceExport(p.name, p.service, p.tag...)); err != nil {
			return err
		}
	}
	if p.stream != "" {
		if err := exports.Add(NewStreamExport(p.name, p.stream, p.tag...)); err != nil {
			return err
		}
	}
	return exports.Store()
}
