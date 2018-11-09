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
	"io/ioutil"
	"os"
	"strconv"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const SeedKeyEnv = "NSC_SEED_KEY"
const TestEnv = "NSC_TEST"

var Version = "DEVELOPMENT"

var cfgFile string
var seedKeyPath string
var ngsStore *store.Store

// show some other hidden commands if the env is set
var show, _ = strconv.ParseBool(os.Getenv(TestEnv))

func getStore() (*store.Store, error) {
	if ngsStore == nil {
		storeDir, err := store.FindCurrentStoreDir()
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

func GetSeedPath() string {
	if seedKeyPath == "" {
		seedKeyPath = os.Getenv(SeedKeyEnv)
	}
	return seedKeyPath
}

func GetKey(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("public key or keypath must be provided (--public-key)")
	}

	_, err := nkeys.FromPublicKey([]byte(value))
	if err != nil {
		d, err := ioutil.ReadFile(value)
		if err != nil {
			return "", fmt.Errorf("error reading public key: %v", err)
		}

		value = string(d)
		_, err = nkeys.FromPublicKey(d)
		if err != nil {
			return "", fmt.Errorf("error reading public key: %v", err)
		}
	}
	return value, nil
}

func GetSeed() (nkeys.KeyPair, error) {
	p := GetSeedPath()
	if p == "" {
		return nil, fmt.Errorf("private key or keypath must be provided (--private-key, -K or in $%s)", SeedKeyEnv)
	}

	kp, err := nkeys.FromSeed([]byte(p))
	if err != nil {
		d, err := ioutil.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("error reading private key: %v", err)
		}

		kp, err := nkeys.FromSeed(d)
		if err != nil {
			return nil, fmt.Errorf("error reading private key: %v", err)
		}

		if err := ValidateMatchesPublicKey(kp); err != nil {
			return nil, err
		}
	}

	return kp, nil
}

func ValidateMatchesPublicKey(kp nkeys.KeyPair) error {
	s, err := getStore()
	pk, err := s.GetPublicKey()
	if err != nil {
		return err
	}
	vv, err := kp.PublicKey()
	if err != nil {
		return fmt.Errorf("error extracting public key from private: %v", err)
	}
	if pk != string(vv) {
		return fmt.Errorf("invalid context - the public key extracted from the private key %q doesn't match the public key associated with the profile %q", string(vv), pk)
	}
	return nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nsc",
	Short: "NSC enables you to create and manage NATS account and user configurations",
	Long: `The ncs tool allows you to create NATS account, users and manage their permissions.

The nsc cli creates accounts, users, and JWT tokens that provide access
to your users and services.`,
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		_, err := getStore()
		if err != nil {
			return err
		}
		return nil
	},
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
	hoistFlags(rootCmd)
}

// hostFlags adds persistent flags that would be added by the cobra framework
// but are not because the unit tests are testing the command directly
func hoistFlags(cmd *cobra.Command) *cobra.Command {
	cmd.PersistentFlags().StringVarP(&seedKeyPath, "private-key", "K", "", "private key")
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
