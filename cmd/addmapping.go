// Copyright 2021 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createAddMappingCmd() *cobra.Command {
	var params AddMappingParams
	cmd := &cobra.Command{
		Use:          "mapping",
		Short:        "Add (or modify) a mapping entry",
		Args:         MaxArgs(0),
		Example:      params.longHelp(),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP((*string)(&params.from), "from", "f", "", "map from subject (required)")
	cmd.Flags().StringVarP((*string)(&params.to.Subject), "to", "t", "", "to subject (required)")
	cmd.Flags().Uint8VarP(&params.to.Weight, "weight", "", 0, "weight [1-100] of this mapping entry (default: 100)")
	cmd.Flags().StringVarP(&params.to.Cluster, "cluster", "", "", "in which cluster this mapping should apply")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddMappingCmd())
}

type AddMappingParams struct {
	AccountContextParams
	SignerParams
	from  jwt.Subject
	to    jwt.WeightedMapping
	claim *jwt.AccountClaims
}

func (p *AddMappingParams) longHelp() string {
	s := `toolName add mapping --from "a" --to "b"
# to modify an entry, say to set a weight after the fact
toolName add mapping --from "a" --to "b" --weight 50
# to add two entries from one subject, set weights and execute multiple times
toolName add mapping --from "a" --to "c" --weight 50
`
	return strings.Replace(s, "toolName", GetToolName(), -1)
}

func (p *AddMappingParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	return nil
}

func (p *AddMappingParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *AddMappingParams) Load(ctx ActionCtx) error {
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

func (p *AddMappingParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *AddMappingParams) Validate(ctx ActionCtx) error {

	var err error
	if p.from == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("from subject is required")
	}
	if p.to.Subject == "" {
		return errors.New("to subject is required")
	}

	if p.claim.Mappings == nil {
		p.claim.Mappings = jwt.Mapping{}
	}

	m := p.to
	if v, ok := (p.claim.Mappings)[p.from]; ok {
		set := false
		for i, w := range v {
			if w.Subject == m.Subject && w.Cluster == m.Cluster {
				v[i] = m
				set = true
				break
			}
		}
		if !set {
			p.claim.Mappings[p.from] = append(v, m)
		}
	} else {
		p.claim.Mappings[p.from] = []jwt.WeightedMapping{m}
	}
	var vr jwt.ValidationResults
	p.claim.Mappings.Validate(&vr)
	if vr.IsBlocking(true) {
		return fmt.Errorf("mapping validation failed: %v", vr.Errors())
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return fmt.Errorf("mapping %s", err)
	}

	return nil
}

func (p *AddMappingParams) Run(ctx ActionCtx) (store.Status, error) {
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(false)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		r.AddOK("added mapping %s -> %s, weight %d%%", p.from, p.to.Subject, p.to.GetWeight())
	}
	return r, err
}
