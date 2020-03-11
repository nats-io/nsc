/*
 * Copyright 2018-2019 The NATS Authors
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
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage keys for operators, accounts, and users",
}

func init() {
	GetRootCmd().AddCommand(keysCmd)
	keysCmd.AddCommand(createMigrateKeysCmd())
}

func createMigrateKeysCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "migrate",
		Short: "migrates keystore to new layout, original keystore is preserved",
		RunE: func(cmd *cobra.Command, args []string) error {
			migration, err := store.KeysNeedMigration()
			if err != nil {
				return err
			}
			if !migration {
				cmd.Printf("keystore %#q does not need migration\n", AbbrevHomePaths(store.GetKeysDir()))
				return nil
			}

			old, err := store.Migrate()
			if err != nil {
				return err
			}
			cmd.Printf("keystore %#q was migrated - old store was renamed to %#q - remove at your convenience\n",
				AbbrevHomePaths(store.GetKeysDir()),
				AbbrevHomePaths(old))

			return nil
		},
	}

	return cmd
}
