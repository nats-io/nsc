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

var WideFlag bool
var Wide = noopNameFilter

type WideFun = func(a string) string

func noopNameFilter(a string) string {
	return a
}

func friendlyNameFilter() (WideFun, error) {
	m, err := friendlyNames(GetConfig().Operator)
	if err != nil {
		return nil, err
	}
	return func(a string) string {
		v := m[a]
		if v == "" {
			v = a
		}
		return v
	}, nil
}

var describeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Describe assets such as operators, accounts, users, and jwt files",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		if WideFlag {
			Wide = noopNameFilter
		} else {
			Wide, err = friendlyNameFilter()
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	GetRootCmd().AddCommand(describeCmd)
	describeCmd.PersistentFlags().BoolVarP(&WideFlag, "long-ids", "W", false, "display account ids on imports")
}
