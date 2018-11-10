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
	"path/filepath"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

type CreateClusterParams struct {
	name    string
	dir     string
	kp      nkeys.KeyPair
	keyFile string
}

func (p *CreateClusterParams) Validate() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(dir) {
		p.dir = filepath.Join(dir, p.dir)
	}

	if p.name == "" {
		p.name = filepath.Base(p.dir)
	}

	if p.kp == nil {
		if KeyPathFlag == "" {
			p.kp, err = nkeys.CreateCluster()
			if err != nil {
				return err
			}
		} else {
			p.kp, err = ResolveKeyFlag()
			if err != nil {
				return err
			}
			pk, err := p.kp.PublicKey()
			if err != nil {
				return err
			}
			if !nkeys.IsValidPublicClusterKey(pk) {
				return fmt.Errorf("private key is not an cluster private key")
			}
		}
	}

	return nil
}

func (p *CreateClusterParams) Run() error {
	if KeyPathFlag == "" {
		// save the generated key
		seed, err := p.kp.Seed()
		if err != nil {
			return err
		}

		keyDir := GetKeysDir()
		p.keyFile = filepath.Join(keyDir, p.name+".nk")
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return fmt.Errorf("error creating directory %q: %v", keyDir, err)
		}
		if err := ioutil.WriteFile(p.keyFile, seed, 0600); err != nil {
			return fmt.Errorf("error storing keyfile %q: %v", p.keyFile, err)
		}
	}

	_, err := store.CreateStore(p.dir, p.name, p.kp)

	return err
}

func createClusterCmd() *cobra.Command {
	var p CreateClusterParams
	cmd := &cobra.Command{
		Use:     "cluster",
		Short:   "Create a cluster configuration directory",
		Example: "create cluster --name mycluster <dirpath>",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				p.dir = "."
			}
			if len(args) == 1 {
				p.dir = args[0]
			}

			if err := p.Validate(); err != nil {
				return err
			}

			if err := p.Run(); err != nil {
				return err
			}

			if p.keyFile != "" {
				cmd.Printf("Generated cluster key - private key stored %q\n", p.keyFile)
			}
			cmd.Printf("Success! - created cluster directory %q\n", p.dir)

			return nil
		},
	}

	cmd.Flags().StringVarP(&p.name, "name", "n", "", "name for the cluster, if not specified uses <dirname>")

	return cmd
}

func init() {
	createCmd.AddCommand(createClusterCmd())
}
