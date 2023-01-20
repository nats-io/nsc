/*
 * Copyright 2018-2022 The NATS Authors
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
	"io"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

var ConfigDirFlag string
var KeysDirFlag string
var DataDirFlag string

var KeyPathFlag string
var InteractiveFlag bool
var NscCwdOnly bool
var ErrNoOperator = errors.New("set an operator -- 'nsc env -o operatorName'")

type InterceptorFn func(ctx ActionCtx, params interface{}) error

func GetStoreForOperator(operator string) (*store.Store, error) {
	config := GetConfig()
	if config.StoreRoot == "" {
		return nil, errors.New("no stores available")
	}
	if err := IsValidDir(config.StoreRoot); err != nil {
		return nil, err
	}

	if operator != "" {
		config.Operator = operator
	}

	if config.Operator == "" {
		config.SetDefaults()
		if config.Operator == "" {
			return nil, ErrNoOperator
		}
	}

	fp := filepath.Join(config.StoreRoot, config.Operator)
	ngsStore, err := store.LoadStore(fp)
	if err != nil {
		return nil, err
	}

	if config.Account != "" {
		ngsStore.DefaultAccount = config.Account
	}
	return ngsStore, nil
}

func GetStore() (*store.Store, error) {
	return GetStoreForOperator("")
}

func ResolveKeyFlag() (nkeys.KeyPair, error) {
	if KeyPathFlag != "" {
		kp, err := store.ResolveKey(KeyPathFlag)
		if err != nil {
			return nil, err
		}
		return kp, nil
	}
	return nil, nil
}

func GetRootCmd() *cobra.Command {
	return rootCmd
}

func precheckDataStore(cmd *cobra.Command) error {
	if store, _ := GetStore(); store != nil {
		if c, _ := store.ReadOperatorClaim(); c != nil && c.Version == 1 {
			if c.Version > 2 {
				return fmt.Errorf("the store %#q is at version %d. To upgrade nsc - type `%s update`",
					store.GetName(), c.Version, os.Args[0])
			} else if c.Version == 1 {
				allowCmdWithJWTV1Store := cmd.Name() == "upgrade-jwt" || cmd.Name() == "env" || cmd.Name() == "help" || cmd.Name() == "update"
				if !allowCmdWithJWTV1Store && cmd.Name() == "operator" {
					for _, v := range addCmd.Commands() {
						if v == cmd {
							allowCmdWithJWTV1Store = true
							break
						}
					}
				}
				if !allowCmdWithJWTV1Store {
					//lint:ignore ST1005 this message is shown to the user
					return fmt.Errorf(`This version of nsc only supports jwtV2. 
If you are using a managed service, check your provider for 
instructions on how to update your project. In most cases 
all you need to do is:
"%s add operator --force -u <url provided by your service>"

If your service is well known, such as Synadia's NGS:
"%s add operator --force -u synadia"

If you are the operator, and you have your operator key, to 
upgrade the v1 store %#q - type:
"%s upgrade-jwt"

Alternatively you can downgrade' %q to a compatible version using: 
"%s update --version 0.5.0"
`,
						os.Args[0], os.Args[0], store.GetName(), os.Args[0], os.Args[0], os.Args[0])
				}
			}
		}
	}
	return nil
}

func precheckKeyStore(cmd *cobra.Command) error {
	if cmd.Name() == "migrate" && cmd.Parent().Name() == "keys" {
		return nil
	}
	// check if we need to perform any kind of migration
	needsUpdate, err := store.KeysNeedMigration()
	if err != nil {
		return err
	}
	if needsUpdate {
		cmd.SilenceUsage = true
		return fmt.Errorf("the keystore %#q needs migration - type `%s keys migrate` to update", AbbrevHomePaths(store.GetKeysDir()), os.Args[0])
	}
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "nsc",
	Short: "nsc creates NATS operators, accounts, users, and manage their permissions.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		// if the flag is set we use it, if not check the old env
		if ConfigDirFlag != "" {
			if ConfigDirFlag, err = Expand(ConfigDirFlag); err != nil {
				return err
			}
		} else if os.Getenv(NscHomeEnv) != "" {
			if ConfigDirFlag, err = Expand(os.Getenv(NscHomeEnv)); err != nil {
				return err
			}
		}

		if DataDirFlag != "" {
			if DataDirFlag, err = Expand(DataDirFlag); err != nil {
				return err
			}
		}

		if KeysDirFlag != "" {
			if KeysDirFlag, err = Expand(KeysDirFlag); err != nil {
				return err
			}
		} else if os.Getenv(store.NKeysPathEnv) != "" {
			if KeysDirFlag, err = Expand(os.Getenv(store.NKeysPathEnv)); err != nil {
				return err
			}
		}

		if _, err = LoadOrInit(ConfigDirFlag, DataDirFlag, KeysDirFlag); err != nil {
			return err
		}
		// check that the store is compatible
		if err := precheckDataStore(cmd); err != nil {
			return err
		}
		// intercept migrate keys
		if err := precheckKeyStore(cmd); err != nil {
			return err
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// print command help by default
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := ExecuteWithWriter(rootCmd.OutOrStderr())
	if err != nil {
		os.Exit(1)
	}
}

// ExecuteWithWriter adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
// But writer is decided by the caller function
// returns error than os.Exit(1)
func ExecuteWithWriter(out io.Writer) error {
	cli.SetOutput(out)
	if err := GetRootCmd().Execute(); err != nil {
		return err
	}
	return nil
}

func SetEnvOptions() {
	if _, ok := os.LookupEnv(NscNoGitIgnoreEnv); ok {
		store.NscNotGitIgnore = true
	}
	if _, ok := os.LookupEnv(NscCwdOnlyEnv); ok {
		NscCwdOnly = true
	}
	if f, ok := os.LookupEnv(NscRootCasNatsEnv); ok {
		rootCAsFile = strings.TrimSpace(f)
		rootCAsNats = nats.RootCAs(rootCAsFile)
	}
	key, okKey := os.LookupEnv(NscTlsKeyNatsEnv)
	cert, okCert := os.LookupEnv(NscTlsCertNatsEnv)
	if okKey || okCert {
		tlsKeyNats = nats.ClientCert(cert, key)
	}
}

func init() {
	SetEnvOptions()
	root := GetRootCmd()
	root.Flags().BoolP("version", "v", false, "version for nsc")
	HoistRootFlags(root)
}

// HoistRootFlags adds persistent flags that would be added by the cobra framework
// but are not because the unit tests are testing the command directly
func HoistRootFlags(cmd *cobra.Command) *cobra.Command {
	cmd.PersistentFlags().StringVarP(&KeyPathFlag, "private-key", "K", "", "Key used to sign. Can be specified as role (where applicable),\npublic key (private portion is retrieved)\nor file path to a private key or private key ")
	cmd.PersistentFlags().BoolVarP(&InteractiveFlag, "interactive", "i", false, "ask questions for various settings")

	cmd.PersistentFlags().StringVarP(&ConfigDirFlag, "config-dir", "", "", "nsc config directory")
	cmd.PersistentFlags().StringVarP(&DataDirFlag, "data-dir", "", "", "nsc data store directory")
	cmd.PersistentFlags().StringVarP(&KeysDirFlag, "keystore-dir", "", "", "nsc keystore directory")

	return cmd
}
