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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nsc/cmd/store"

	nats "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

func createReplyCmd() *cobra.Command {
	var params RepParams
	var cmd = &cobra.Command{
		Use:     "reply",
		Short:   "Reply to requests on a subject on a NATS account",
		Example: "nsc tool reply <subject> <opt_reply>\nnsc tool reply --queue <name> subject <opt_reply>",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.queue, "queue", "q", "", "reply queue name")
	cmd.Flags().IntVarP(&params.maxMessages, "max-messages", "", -1, "max messages")
	params.BindFlags(cmd)
	return cmd
}

func init() {
	toolCmd.AddCommand(createReplyCmd())
	hidden := createReplyCmd()
	hidden.Hidden = true
	hidden.Example = "nsc reply <subject> <opt_reply>\nnsc tool reply --queue <name> subject <opt_reply>"
	GetRootCmd().AddCommand(hidden)
}

type RepParams struct {
	AccountUserContextParams
	credsPath   string
	natsURLs    []string
	queue       string
	maxMessages int
}

func (p *RepParams) SetDefaults(ctx ActionCtx) error {
	return p.AccountUserContextParams.SetDefaults(ctx)
}

func (p *RepParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountUserContextParams.Edit(ctx)
}

func (p *RepParams) Load(ctx ActionCtx) error {
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

func (p *RepParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *RepParams) Validate(ctx ActionCtx) error {
	if err := p.AccountUserContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.maxMessages == 0 {
		return errors.New("max-messages must be greater than zero")
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

func (p *RepParams) Run(ctx ActionCtx) (store.Status, error) {
	opts := createDefaultToolOptions("nscreply", ctx)
	opts = append(opts, nats.UserCredentials(p.credsPath))
	nc, err := nats.Connect(strings.Join(p.natsURLs, ","), opts...)
	if err != nil {
		return nil, err
	}
	defer nc.Close()

	subj := ctx.Args()[0]
	var resp []byte
	if len(ctx.Args()) > 1 {
		resp = []byte(ctx.Args()[1])
	}
	// we are doing sync subs because we want the cli to cleanup properly
	// when the command returns
	var sub *nats.Subscription
	if p.queue != "" {
		sub, err = nc.QueueSubscribeSync(subj, p.queue)
		if err != nil {
			return nil, err
		}
	} else {
		sub, err = nc.SubscribeSync(subj)
		if err != nil {
			return nil, err
		}
	}

	if p.maxMessages > 0 {
		if err := sub.AutoUnsubscribe(p.maxMessages); err != nil {
			return nil, err
		}
		ctx.CurrentCmd().Printf("listening on [%s] for %d messages\n", subj, p.maxMessages)
	} else {
		ctx.CurrentCmd().Printf("listening on [%s]\n", subj)
	}

	if err := nc.Flush(); err != nil {
		return nil, err
	}

	i := 0
	for {
		msg, err := sub.NextMsg(10 * time.Second)
		if err == nats.ErrTimeout {
			continue
		}
		if err == nats.ErrMaxMessages {
			break
		}
		if err == nats.ErrConnectionClosed {
			break
		}
		if err != nil {
			return nil, err
		}

		i++
		payload := msg.Data
		if resp != nil {
			payload = resp
		}
		if msg.Reply == "" {
			ctx.CurrentCmd().Printf("[#%d] ignoring request on [%s]: no reply subject\n", i, msg.Subject)
			continue
		}
		ctx.CurrentCmd().Printf("[#%d] received on [%s]: '%s'\n", i, msg.Subject, string(msg.Data))

		if err := nc.Publish(msg.Reply, []byte(payload)); err != nil {
			ctx.CurrentCmd().Printf("[#%d] error responding: '%v'\n", i, err)
			return nil, err
		}
	}

	return nil, nil
}
