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

	"github.com/nats-io/nsc/cmd/store"

	nats "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

func createPubCmd() *cobra.Command {
	var params PubParams
	var cmd = &cobra.Command{
		Use:     "pub",
		Short:   "Publish to a subject from a NATS account",
		Example: "nsc tool pub <subject> <opt_payload>",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	params.BindFlags(cmd)
	return cmd
}

func init() {
	toolCmd.AddCommand(createPubCmd())
	hidden := createPubCmd()
	hidden.Hidden = true
	hidden.Example = "nsc pub <subject> <opt_payload>"
	GetRootCmd().AddCommand(hidden)
}

// ToolPubParams is the driving struct for the list plans action
type PubParams struct {
	AccountUserContextParams
	credsPath string
	natsURLs  []string
}

func (p *PubParams) SetDefaults(ctx ActionCtx) error {
	return p.AccountUserContextParams.SetDefaults(ctx)
}

func (p *PubParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountUserContextParams.Edit(ctx)
}

func (p *PubParams) Load(ctx ActionCtx) error {
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

func (p *PubParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *PubParams) Validate(ctx ActionCtx) error {
	if err := p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.credsPath == "" {
		return fmt.Errorf("a creds file for account %q/%q was not found", p.AccountContextParams.Name, p.UserContextParams.Name)
	}

	_, err := os.Stat(p.credsPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("%v: %#q", err, p.credsPath)
	}
	if len(p.natsURLs) == 0 {
		return fmt.Errorf("operator %q doesn't have operator_service_urls set", ctx.StoreCtx().Operator.Name)
	}
	return nil
}

func (p *PubParams) Run(ctx ActionCtx) (store.Status, error) {
	opts := createDefaultToolOptions("nsc_pub", ctx)
	opts = append(opts, nats.UserCredentials(p.credsPath))
	nc, err := nats.Connect(strings.Join(p.natsURLs, ", "), opts...)
	if err != nil {
		return nil, err
	}
	defer nc.Close()

	subj := ctx.Args()[0]
	payload := ""
	if len(ctx.Args()) > 1 {
		payload = ctx.Args()[1]
	}
	if err := nc.Publish(subj, []byte(payload)); err != nil {
		return nil, err
	}
	if err := nc.Flush(); err != nil {
		return nil, err
	}

	ctx.CurrentCmd().Printf("Published [%s] : %q\n", subj, payload)

	return nil, nil
}
