/*
 * Copyright 2021 The NATS Authors
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

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteMappingCmd() *cobra.Command {
	var params DeleteMappingParams
	cmd := &cobra.Command{
		Use:          "mapping",
		Short:        "Delete a mapping",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP((*string)(&params.from), "from", "f", "", "map from subject (required)")
	cmd.Flags().StringVarP((*string)(&params.to), "to", "t", "", "to subject. When present, only that particular mapping is removed. Otherwise all mappings for from subject are.")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteMappingCmd())
}

type DeleteMappingParams struct {
	AccountContextParams
	SignerParams
	claim *jwt.AccountClaims
	from  jwt.Subject
	to    jwt.Subject
}

func (p *DeleteMappingParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *DeleteMappingParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteMappingParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	return nil
}

func (p *DeleteMappingParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DeleteMappingParams) Validate(ctx ActionCtx) error {
	if p.from == "" {
		return fmt.Errorf("from subject is required")
	}
	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteMappingParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	if p.to != "" {
		list := p.claim.Mappings[p.from]
		for i, l := range list {
			if l.Subject == p.to {
				if i == 0 {
					if len(list) == 1 {
						delete(p.claim.Mappings, p.from)
					} else {
						p.claim.Mappings[p.from] = list[1:]
					}
				} else {
					p.claim.Mappings[p.from] = append(list[0:i], list[i+i:]...)
				}
				break
			}
		}
	}
	if p.to == "" || len(p.claim.Mappings[p.from]) == 0 {
		delete(p.claim.Mappings, p.from)
	}
	if len(p.claim.Mappings) == 0 {
		p.claim.Mappings = nil
	}
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	if p.to == "" {
		r.AddOK("deleted all mapping for %s", p.from)
	} else {
		r.AddOK("deleted mapping %s -> %s", p.from, p.to)
	}
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(token))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
	}
	return r, nil
}
