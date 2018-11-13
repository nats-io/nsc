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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/kstore"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddServerCmd() *cobra.Command {
	var params AddServerParams
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Add a server (operator only)",
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if params.generate {
				if kstore.KeyPathFlag == "" {
					cmd.Printf("Generated cluster key - private key stored %q\n", params.clusterKeyPath)
				}
				cmd.Printf("Generated server key - private key stored %q\n", params.serverKeyPath)
			} else {
				cmd.Printf("Success! - added server %q\n", params.Name)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.Name, "name", "", "", "server name")
	cmd.Flags().StringVarP(&params.Name, "cluster-name", "", "", "server name")

	cmd.Flags().StringVarP(&params.serverKeyPath, "public-key", "k", "", "public key identifying the server")
	cmd.Flags().BoolVarP(&params.generate, "generate-nkeys", "", false, "generate nkeys")

	cmd.MarkFlagRequired("name")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddServerCmd())
}

type AddServerParams struct {
	clusterKP      nkeys.KeyPair
	clusterKeyPath string
	clusterName    string
	generate       bool
	operatorKP     nkeys.KeyPair
	serverKeyPath  string
	serverKP       nkeys.KeyPair
	jwt.ServerClaims
}

func (p *AddServerParams) Validate() error {
	if p.serverKeyPath != "" && p.generate {
		return errors.New("specify one of --public-key or --generate-nkeys")
	}

	s, err := getStore()
	if err != nil {
		return err
	}
	if p.clusterName == "" {
		cNames, err := s.ListSubContainers(store.Clusters)
		if err != nil {
			return err
		}
		c := len(cNames)
		if c == 0 {
			return errors.New("no clusters defined - add cluster first")
		}
		if c == 1 {
			p.clusterName = cNames[0]
		}
		if c > 1 {
		} else if len(cNames) > 1 {
			return errors.New("multiple clusters found - specify --cluster-name")
		}
	}

	if s.Has(store.Clusters, p.clusterName, store.Servers, store.JwtName(p.Name)) {
		return fmt.Errorf("cluster %q already has a server named %q", p.clusterName, p.Name)
	}

	if err = p.resolveClusterKey(); err != nil {
		return err
	}

	if err = p.resolveServerKey(); err != nil {
		return err
	}

	return nil
}

func (p *AddServerParams) resolveClusterKey() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	ks := kstore.NewKeyStore()
	// sign key - operator
	p.clusterKP, err = kstore.ResolveKeyFlag()
	if err != nil {
		return err
	}
	if p.clusterKP == nil {
		p.clusterKP, err = ks.GetClusterKey(s.GetName(), p.clusterName)
		if err != nil {
			return err
		}
		if p.clusterKP == nil {
			return fmt.Errorf("specify the cluster private key with --private-key for signing the server")
		}
	}

	if !kstore.KeyPairTypeOk(nkeys.PrefixByteCluster, p.clusterKP) {
		return fmt.Errorf("resolved --private-key key is not an operator key")
	}
	return nil
}

func (p *AddServerParams) resolveServerKey() error {
	var err error
	if p.serverKeyPath != "" {
		kp, err := kstore.ResolveKey(p.serverKeyPath)
		if err != nil {
			return err
		}
		if !kstore.KeyPairTypeOk(nkeys.PrefixByteServer, kp) {
			return fmt.Errorf("specified server key is not a server key")
		}
		p.serverKP = kp
	}

	if p.generate {
		p.serverKP, err = nkeys.CreateServer()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *AddServerParams) Run() error {
	pkd, err := p.serverKP.PublicKey()
	if err != nil {
		return err
	}
	p.Subject = string(pkd)

	token, err := p.ServerClaims.Encode(p.clusterKP)
	if err != nil {
		return err
	}

	s, err := getStore()
	if err != nil {
		return err
	}

	if err := s.StoreClaim([]byte(token)); err != nil {
		return err
	}

	if p.generate {
		ks := kstore.NewKeyStore()
		if p.clusterKeyPath == "" {
			p.clusterKeyPath, err = ks.Store(s.Info.Name, p.Name, p.clusterKP)
			if err != nil {
				return err
			}
		}

		if p.serverKeyPath == "" {
			p.serverKeyPath, err = ks.Store(s.Info.Name, p.Name, p.serverKP)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
