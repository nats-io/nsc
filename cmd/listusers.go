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

func createListUsersCmd() *cobra.Command {
	var params ListUsersParams
	var cmd = &cobra.Command{
		Use:   "users",
		Short: "Lists users",
		RunE: func(cmd *cobra.Command, args []string) error {
			users, err := ListUsers()
			if err != nil {
				return err
			}

			if len(users) == 0 {
				cmd.Println("Account has no users. Add one with 'add user' first.")
				return nil
			}

			if params.match != "" {
				var buf []User
				for _, v := range users {
					if v.Matches(params.match) {
						buf = append(buf, v)
					}
				}
				users = buf
			}

			PrintUsers(&users)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.match, "match", "m", "", "match key, name or tag")
	return cmd
}

func init() {
	listCmd.AddCommand(createListUsersCmd())
}

type ListUsersParams struct {
	match string
}
