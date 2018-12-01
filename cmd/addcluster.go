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
	"github.com/spf13/cobra"
)

func createAddClusterCmd() *cobra.Command {
	var params AddClusterParams
	cmd := &cobra.Command{
		Use:          "cluster",
		Short:        "Add a cluster (operator only)",
		Example:      `nsc add cluster --name mycluster --trusted-accounts actkey1,actkey2 --trusted-operators opkey1,opkey2`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if params.generated {
				cmd.Printf("Generated cluster key - private key stored %q\n", params.keyPath)
			}
			cmd.Printf("Success! - added cluster %q\n", params.name)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "cluster name")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the cluster")
	cmd.Flags().StringSliceVar(&params.accounts, "trusted-accounts", nil, "trusted account public keys")
	cmd.Flags().StringSliceVar(&params.operators, "trusted-operators", nil, "trusted operator public keys")
	cmd.Flags().StringVar(&params.accountUrlTemplate, "account-url-template", "", "template url for retrieving account jwts by account id")
	cmd.Flags().StringVar(&params.operatorUrlTemplate, "operator-url-template", "", "template url for retrieving operator jwts by operator id")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddClusterCmd())
}

type AddClusterParams struct {
	Entity
	TimeParams
	SignerParams
	expiry              int64
	start               int64
	accounts            []string
	operators           []string
	accountUrlTemplate  string
	operatorUrlTemplate string
}

func (p *AddClusterParams) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, false, ctx)
	p.create = true
	p.Entity.kind = nkeys.PrefixByteCluster
	p.editFn = p.editClusterClaim
	return nil
}

func (p *AddClusterParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.Entity.Edit(); err != nil {
		return err
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddClusterParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *AddClusterParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *AddClusterParams) Validate(ctx ActionCtx) error {
	var err error
	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("cluster name is required")
	}

	if err = p.TimeParams.Validate(); err != nil {
		return err
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	for _, v := range p.accounts {
		if !nkeys.IsValidPublicAccountKey(v) {
			return fmt.Errorf("%q is not a valid account public key", v)
		}
	}

	for _, v := range p.operators {
		if !nkeys.IsValidPublicOperatorKey(v) {
			return fmt.Errorf("%q is not a valid operator public key", v)
		}
	}

	return p.Valid()
}

func (p *AddClusterParams) Run(ctx ActionCtx) error {

	if err := p.Entity.StoreKeys(ctx.StoreCtx().Store.GetName()); err != nil {
		return err
	}

	if err := p.Entity.GenerateClaim(p.signerKP, ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddClusterParams) editClusterClaim(c interface{}, ctx ActionCtx) error {
	cc, ok := c.(*jwt.ClusterClaims)
	if !ok {
		return errors.New("unable to cast to cluster claim")
	}

	if ctx != nil {
		if ctx.CurrentCmd().Flag("account-url-template").Changed {
			cc.AccountURL = p.accountUrlTemplate
		}

		if ctx.CurrentCmd().Flag("operator-url-template").Changed {
			cc.OperatorURL = p.operatorUrlTemplate
		}
	}

	var accounts jwt.StringList
	accounts.Add(cc.Accounts...)
	accounts.Add(p.accounts...)
	cc.Accounts = accounts

	var operators jwt.StringList
	operators.Add(cc.Trust...)
	operators.Add(p.operators...)
	cc.Trust = operators

	if p.TimeParams.IsStartChanged() {
		cc.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		cc.Expires, _ = p.TimeParams.ExpiryDate()
	}
	return nil
}
