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
	operatorKP     nkeys.KeyPair
	clusterKP      nkeys.KeyPair
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

	ctx, err := s.GetContext()
	if err != nil {
		return fmt.Errorf("error getting context: %v", err)
	}

	if s.Has(store.Clusters, p.Name) {
		return fmt.Errorf("cluster %q already exists", p.Name)
	}

	p.operatorKP, err = ctx.ResolveKey(nkeys.PrefixByteOperator, store.KeyPathFlag)
	if err != nil {
		return fmt.Errorf("specify the operator private key with --private-key to use for signing the cluster")
	}

	if p.generate {
		p.clusterKP, err = nkeys.CreateCluster()
		if err != nil {
			return fmt.Errorf("error generating an cluster key: %v", err)
		}
	} else {
		p.clusterKP, err = ctx.ResolveKey(nkeys.PrefixByteCluster, p.clusterKeyPath)
		if err != nil {
			return fmt.Errorf("error resolving account key: %v", err)
		}
	}

	return nil
}

func (p *AddClusterParams) Run() error {
	pkd, err := p.clusterKP.PublicKey()
	if err != nil {
		return err
	}
	p.Subject = string(pkd)

	token, err := p.ClusterClaims.Encode(p.operatorKP)
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
		ks := store.NewKeyStore()
		p.clusterKeyPath, err = ks.Store(s.Info.Name, p.Name, p.clusterKP)
		if err != nil {
			return err
		}
	}

	return nil
}
