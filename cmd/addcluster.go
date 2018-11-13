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

func createAddClusterCmd() *cobra.Command {
	var params AddClusterParams
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Add a cluster (operator only)",
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if params.generate {
				cmd.Printf("Generated cluster key - private key stored %q\n", params.clusterKeyPath)
			} else {
				cmd.Printf("Success! - added cluster %q\n", params.Name)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.Name, "name", "", "", "cluster name")

	cmd.Flags().StringVarP(&params.clusterKeyPath, "public-key", "k", "", "public key identifying the cluster")
	cmd.Flags().BoolVarP(&params.generate, "generate-nkeys", "", false, "generate nkeys")

	cmd.MarkFlagRequired("name")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddClusterCmd())
}

type AddClusterParams struct {
	okp            nkeys.KeyPair
	ckp            nkeys.KeyPair
	clusterKeyPath string
	generate       bool
	jwt.ClusterClaims
}

func (p *AddClusterParams) Validate() error {
	if p.clusterKeyPath != "" && p.generate {
		return errors.New("specify one of --public-key or --generate-nkeys")
	}

	s, err := getStore()
	if err != nil {
		return err
	}

	if s.Has(store.Clusters, p.Name) {
		return fmt.Errorf("cluster %q already exists", p.Name)
	}

	if err = p.resolveOperatorKey(); err != nil {
		return err
	}

	if err = p.resolveClusterKey(); err != nil {
		return err
	}

	return nil
}

func (p *AddClusterParams) resolveOperatorKey() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	ks := kstore.NewKeyStore()
	// sign key - operator
	p.okp, err = kstore.ResolveKeyFlag()
	if err != nil {
		return err
	}
	if p.okp == nil {
		p.okp, err = ks.GetOperatorKey(s.GetName())
		if err != nil {
			return err
		}
		if p.okp == nil {
			return fmt.Errorf("specify the operator private key with --private-key to use for signing the cluster")
		}
	}

	if !kstore.KeyPairTypeOk(nkeys.PrefixByteOperator, p.okp) {
		return fmt.Errorf("resolved --private-key key is not an operator key")
	}
	return nil
}

func (p *AddClusterParams) resolveClusterKey() error {
	var err error
	if p.clusterKeyPath != "" {
		kp, err := kstore.ResolveKey(p.clusterKeyPath)
		if err != nil {
			return err
		}
		if !kstore.KeyPairTypeOk(nkeys.PrefixByteCluster, kp) {
			return fmt.Errorf("specified public key is not a cluster key")
		}
		p.ckp = kp
	}

	if p.generate {
		p.ckp, err = nkeys.CreateCluster()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *AddClusterParams) Run() error {
	pkd, err := p.ckp.PublicKey()
	if err != nil {
		return err
	}
	p.Subject = string(pkd)

	token, err := p.ClusterClaims.Encode(p.okp)
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
		p.clusterKeyPath, err = ks.Store(s.Info.Name, p.Name, p.ckp)
		if err != nil {
			return err
		}
	}

	return nil
}
