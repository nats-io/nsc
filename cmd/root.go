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
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const SeedKeyEnv = "NSC_SEED_KEY"
const TestEnv = "NSC_TEST"

var Version = "DEVELOPMENT"

var cfgFile string
var ngsStore *store.Store

// show some other hidden commands if the env is set
var show, _ = strconv.ParseBool(os.Getenv(TestEnv))

func getStore() (*store.Store, error) {
	if ngsStore == nil {
		storeDir, err := FindCurrentStoreDir()
		if err != nil {
			return nil, err
		}
		ngsStore, err = store.LoadStore(storeDir)
		if err != nil {
			return nil, err
		}
	}
	return ngsStore, nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nsc",
	Short: "NSC enables you to create and manage NATS account and user configurations",
	Long: `The ncs tool allows you to create NATS account, users and manage their permissions.

The nsc cli creates accounts, users, and JWT tokens that provide access
to your users and services.`,
	Version: Version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cli.SetOutput(rootCmd.OutOrStderr())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	hoistFlags(rootCmd)
}

// hostFlags adds persistent flags that would be added by the cobra framework
// but are not because the unit tests are testing the command directly
func hoistFlags(cmd *cobra.Command) *cobra.Command {
	cmd.PersistentFlags().StringVarP(&KeyPathFromFlag, "private-key", "K", "", "private key")
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

// FindCurrentStoreDir tries to find a store director
// starting with the current working dir
func FindCurrentStoreDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return FindStoreDir(wd)
}

// FindStore starts at the directory provided and tries to
// find a directory containing the public key. This function
// checks dir and then works its way up the folder path.
func FindStoreDir(dir string) (string, error) {
	var err error

	pkp := filepath.Join(dir, store.NSCFile)

	if _, err := os.Stat(pkp); os.IsNotExist(err) {
		parent := filepath.Dir(dir)

		if parent == dir {
			return "", fmt.Errorf("no store directory found")
		}

		return FindStoreDir(parent)
	}

	return dir, err
}
