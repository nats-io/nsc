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

func createToolReqCmd() *cobra.Command {
	var params ReqParams
	var cmd = &cobra.Command{
		Use:     "req",
		Short:   "Send a request to a subject on a NATS account",
		Example: "ngs tool req <subject> <opt_payload>",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	params.BindFlags(cmd)
	cmd.Flags().BoolVarP(&encryptFlag, "encrypt", "E", false, "encrypt payload")
	cmd.Flags().MarkHidden("encrypt")
	cmd.Flags().MarkHidden("decrypt")

	return cmd
}

func init() {
	toolCmd.AddCommand(createToolReqCmd())
	hidden := createToolReqCmd()
	hidden.Hidden = true
	hidden.Example = "ngs tool req <subject> <opt_payload>"
	GetRootCmd().AddCommand(hidden)
}

type ReqParams struct {
	AccountUserContextParams
	credsPath string
	natsURLs  []string
}

func (p *ReqParams) SetDefaults(ctx ActionCtx) error {
	return p.AccountUserContextParams.SetDefaults(ctx)
}

func (p *ReqParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountUserContextParams.Edit(ctx)
}

func (p *ReqParams) Load(ctx ActionCtx) error {
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

func (p *ReqParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ReqParams) Validate(ctx ActionCtx) error {
	if err := p.AccountUserContextParams.Validate(ctx); err != nil {
		return err
	}

	if encryptFlag {
		_, err := ctx.StoreCtx().KeyStore.GetSeed(ctx.StoreCtx().Account.PublicKey)
		if err != nil {
			return fmt.Errorf("unable to get the account private key to encrypt/decrypt the payload: %v", err)
		}
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

func (p *ReqParams) Run(ctx ActionCtx) (store.Status, error) {
	opts := createDefaultToolOptions("nsc_req", ctx)
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

	var seed string
	if encryptFlag {
		// cannot fail if we are here
		seed, _ = ctx.StoreCtx().KeyStore.GetSeed(ctx.StoreCtx().Account.PublicKey)
	}

	out := []byte(payload)
	if encryptFlag {
		out, err = EncryptKV(seed, out)
		if err != nil {
			return nil, err
		}
	}

	if encryptFlag {
		ctx.CurrentCmd().Printf("published encrypted request: [%s] : '%s'\n", subj, payload)
	} else {
		ctx.CurrentCmd().Printf("published request: [%s] : '%s'\n", subj, payload)
	}
	msg, err := nc.Request(subj, out, 5*time.Second)
	if err == nats.ErrTimeout {
		ctx.CurrentCmd().Println("request timed out")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if encryptFlag {
		msg = maybeDecryptMessage(seed, msg)
	}
	ctx.CurrentCmd().Printf("received reply: [%v] : '%s'\n", msg.Subject, string(msg.Data))
	return nil, nil
}
