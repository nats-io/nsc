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
	"strconv"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Version = "DEVELOPMENT"
var cfgFile string
var profileName string
var ngsHome string
var ngsStore *store.Store
var show, _ = strconv.ParseBool(os.Getenv("NGS_TEST"))

func getStore() (*store.Store, error) {
	var err error
	if ngsStore == nil {
		ngsStore, err = store.LoadStore(ngsHome, profileName)
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
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if ngsStore != nil {
			return ngsStore.Close()
		}
		return nil
	},
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
	rootCmd.PersistentFlags().StringVarP(&ngsHome, "nsc-home", "H", "", "nsc home directory")
	rootCmd.PersistentFlags().StringVarP(&profileName, "profile-name", "a", "", "profile name")
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
