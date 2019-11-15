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

func createSubCmd() *cobra.Command {
	var params SubParams
	var cmd = &cobra.Command{
		Use:     "sub",
		Short:   "Subscribe to a subject on a NATS account",
		Example: "nsc tool sub <subject>\nnsc tool --queue <name> subject",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.queue, "queue", "q", "", "subscription queue name")
	cmd.Flags().IntVarP(&params.maxMessages, "max-messages", "", -1, "max messages")
	cmd.Flags().BoolVarP(&encryptFlag, "encrypt", "E", false, "encrypted payload")
	cmd.Flags().MarkHidden("max-messages")
	cmd.Flags().MarkHidden("decrypt")

	params.BindFlags(cmd)
	return cmd
}

func init() {
	toolCmd.AddCommand(createSubCmd())
	hidden := createSubCmd()
	hidden.Hidden = true
	hidden.Example = "nsc sub <subject>\nnsc --queue <name> subject"
	GetRootCmd().AddCommand(hidden)
}

type SubParams struct {
	AccountUserContextParams
	credsPath   string
	natsURLs    []string
	queue       string
	maxMessages int
}

func (p *SubParams) SetDefaults(ctx ActionCtx) error {
	return p.AccountUserContextParams.SetDefaults(ctx)
}

func (p *SubParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountUserContextParams.Edit(ctx)
}

func (p *SubParams) Load(ctx ActionCtx) error {
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

func (p *SubParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *SubParams) Validate(ctx ActionCtx) error {
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

func (p *SubParams) Run(ctx ActionCtx) (store.Status, error) {
	opts := createDefaultToolOptions("nscsub", ctx)
	opts = append(opts, nats.UserCredentials(p.credsPath))
	nc, err := nats.Connect(strings.Join(p.natsURLs, ", "), opts...)
	if err != nil {
		return nil, err
	}
	defer nc.Close()

	subj := ctx.Args()[0]
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
		ctx.CurrentCmd().Printf("Listening on [%s] for %d messages\n", subj, p.maxMessages)
	} else {
		ctx.CurrentCmd().Printf("Listening on [%s]\n", subj)
	}

	if err := nc.Flush(); err != nil {
		return nil, err
	}

	var seed string
	if encryptFlag {
		// cannot fail if we are here
		seed, err = ctx.StoreCtx().KeyStore.GetSeed(ctx.StoreCtx().Account.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to get the account private key to encrypt/decrypt the payload: %v", err)
		}
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
		if encryptFlag {
			msg = maybeDecryptMessage(seed, msg)
		}
		ctx.CurrentCmd().Printf("[#%d] received on [%s]: '%s'\n", i, msg.Subject, string(msg.Data))
	}

	return nil, nil
}

func maybeDecryptMessage(seed string, msg *nats.Msg) *nats.Msg {
	var dmsg nats.Msg
	// last part of the subject will be encrypted
	tokens := strings.Split(msg.Subject, ".")
	k := tokens[len(tokens)-1]
	kk, err := Decrypt(seed, []byte(k))
	if err != nil {
		dmsg.Subject = msg.Subject
	} else {
		tokens[len(tokens)-1] = string(kk)
		dmsg.Subject = strings.Join(tokens, ".")
	}

	dmsg.Data, err = Decrypt(seed, msg.Data)
	if err != nil {
		dmsg.Data = msg.Data
	}
	return &dmsg
}
