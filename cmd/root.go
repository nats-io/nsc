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
	"os"
	"path/filepath"
	"strconv"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const TestEnv = "NSC_TEST"

var KeyPathFlag string
var InteractiveFlag bool
var WideFlag bool
var quietMode bool

var cfgFile string

//lint:ignore U1000 used by tests
var ngsStore *store.Store
var interceptorFn InterceptorFn

// show some other hidden commands if the env is set
var show, _ = strconv.ParseBool(os.Getenv(TestEnv))

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
			return nil, fmt.Errorf("set an operator")
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

// ResetStore to nil for tests
func ResetStore() {
	ngsStore = nil
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

func SetInterceptor(fn InterceptorFn) {
	interceptorFn = fn
}

func RunInterceptor(ctx ActionCtx, params interface{}) error {
	if interceptorFn != nil {
		return interceptorFn(ctx, params)
	}
	return nil
}

func GetRootCmd() *cobra.Command {
	return rootCmd
}

func EnterQuietMode() {
	quietMode = true
}

func SetQuietMode(tf bool) {
	quietMode = tf
}

func QuietMode() bool {
	return quietMode
}

var rootCmd = &cobra.Command{
	Use:   "nsc",
	Short: "NSC enables you to create and manage NATS accounts and user configurations",
	Long: `The nsc tool allows you to create NATS accounts, users and manage their permissions.
The nsc cli creates accounts, users, and JWT tokens that provide access
to your users and services.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
			return fmt.Errorf("the keystore %q needs migration - type `%s keys migrate` to update", AbbrevHomePaths(store.GetKeysDir()), os.Args[0])
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cli.SetOutput(rootCmd.OutOrStderr())
	if err := GetRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	HoistRootFlags(GetRootCmd())
}

// hostFlags adds persistent flags that would be added by the cobra framework
// but are not because the unit tests are testing the command directly
func HoistRootFlags(cmd *cobra.Command) *cobra.Command {
	cmd.PersistentFlags().StringVarP(&KeyPathFlag, "private-key", "K", "", "private key")
	cmd.PersistentFlags().BoolVarP(&InteractiveFlag, "interactive", "i", false, "ask questions for various settings")

	return cmd
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".nsc" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".nsc")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
