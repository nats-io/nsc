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
	"github.com/spf13/cobra"
)

func createListExportsCmd() *cobra.Command {
	var params ListExportsParams
	var cmd = &cobra.Command{
		Use:   "exports",
		Short: "Lists exports",
		RunE: func(cmd *cobra.Command, args []string) error {
			var exports Exports
			if err := exports.Load(); err != nil {
				return err
			}
			var m []*Export
			if params.match != "" {
				m = exports.Match(params.match)
			} else {
				m = exports
			}
			if len(m) == 0 {
				cmd.Println("Account has no exports. Add one by 'add export' first.")
			} else {
				PrintExports(m)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.match, "match", "m", "", "match subject, name or tag")
	return cmd
}

func init() {
	listCmd.AddCommand(createListExportsCmd())
}

type ListExportsParams struct {
	match string
}
