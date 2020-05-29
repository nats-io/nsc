/*
 * Copyright 2018-2019 The NATS Authors
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
	"strings"
	"time"

	"github.com/nats-io/nsc/cmd/store"

	nats "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

func createToolRTTCmd() *cobra.Command {
	var params RttParams
	var cmd = &cobra.Command{
		Use:     "rtt",
		Short:   "Calculate the round trip time to the server",
		Example: "nsc tool rtt",
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	params.BindFlags(cmd)
	return cmd
}

func init() {
	toolCmd.AddCommand(createToolRTTCmd())
	hidden := createToolRTTCmd()
	hidden.Hidden = true
	hidden.Example = "nsc tool rtt"
	GetRootCmd().AddCommand(hidden)
}

type RttParams struct {
	AccountUserContextParams
	credsPath string
	natsURLs  []string
}

func (p *RttParams) SetDefaults(ctx ActionCtx) error {
	return p.AccountUserContextParams.SetDefaults(ctx)
}

func (p *RttParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountUserContextParams.Edit(ctx)
}

func (p *RttParams) Load(ctx ActionCtx) error {
	p.credsPath = ctx.StoreCtx().KeyStore.CalcUserCredsPath(p.AccountContextParams.Name, p.UserContextParams.Name)

	if natsURLFlag != "" {
		p.natsURLs = []string{natsURLFlag}
		return nil
	}

	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	p.natsURLs = oc.OperatorServiceURLs
	return nil
}

func (p *RttParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *RttParams) Validate(ctx ActionCtx) error {
	if err := p.AccountUserContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.credsPath == "" {
		return fmt.Errorf("a creds file for account %q/%q was not found", p.AccountContextParams.Name, p.UserContextParams.Name)
	}
	_, err := os.Stat(p.credsPath)
	if os.IsNotExist(err) {
		return err
	}
	if len(p.natsURLs) == 0 {
		return fmt.Errorf("operator %q doesn't have operator_service_urls set", ctx.StoreCtx().Operator.Name)
	}
	return nil
}

func (p *RttParams) Run(ctx ActionCtx) (store.Status, error) {
	opts := createDefaultToolOptions("nsc_rtt", ctx)
	opts = append(opts, nats.UserCredentials(p.credsPath))
	nc, err := nats.Connect(strings.Join(p.natsURLs, ", "), opts...)
	if err != nil {
		return nil, err
	}
	defer nc.Close()

	if err != nil {
		return nil, err
	}
	start := time.Now()
	if err := nc.Flush(); err != nil {
		return nil, err
	}
	rtt := time.Since(start)
	ctx.CurrentCmd().Printf("round trip time to [%s] = %v\n", nc.ConnectedUrl(), rtt)
	return nil, nil
}
