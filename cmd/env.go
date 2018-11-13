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
	"os"
	"path/filepath"

	"github.com/nats-io/nsc/cmd/kstore"

	"github.com/xlab/tablewriter"

	"github.com/spf13/cobra"
)

const NscPathEnv = "NSC_PATH"

func envSet(varName string) string {
	if os.Getenv(varName) == "" {
		return "No"
	}
	return "Yes"
}

func createEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "env",
		Short:   "Prints the nsc environment",
		Example: "env <optional_path>",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			var err error
			dir, err = filepath.Abs(dir)
			if err != nil {
				return err
			}
			dir = ResolvePath(dir, NscPathEnv)

			table := tablewriter.CreateTable()
			table.UTF8Box()
			table.AddTitle("NSC Environment")
			table.AddHeaders("Variable", "Set", "Effective Value")

			table.AddRow("$"+kstore.NKeysPathEnv, envSet(kstore.NKeysPathEnv), kstore.GetKeysDir())
			table.AddRow("$"+NscPathEnv, envSet(NscPathEnv), dir)

			cmd.Println(table.Render())

			return nil
		},
	}

	return cmd
}

func init() {
	rootCmd.AddCommand(createEnvCmd())
}
