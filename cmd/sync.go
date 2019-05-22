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
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createSyncCommand() *cobra.Command {
	var params SyncCmdParams
	var cmd = &cobra.Command{
		Example: "sync",
		Use:     "sync",
		Args:    MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			cmd.Printf("Success! - account synced\n")
			return nil
		},
	}

	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createSyncCommand())
}

type SyncCmdParams struct {
	AccountContextParams
	ASU string
}

func (p *SyncCmdParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	if p.ASU == "" {
		op, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		p.ASU = op.AccountServerURL
	}
	return nil
}

func (p *SyncCmdParams) validURL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("url cannot be empty")
	}

	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	supported := []string{"http", "https"}

	ok := false
	for _, v := range supported {
		if scheme == v {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("scheme %q is not supported (%v)", scheme, strings.Join(supported, ", "))
	}
	return nil
}

func (p *SyncCmdParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	p.ASU, err = cli.Prompt("Account Server URL", p.ASU, true, p.validURL)
	return err
}

func (p *SyncCmdParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	return err
}

func (p *SyncCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *SyncCmdParams) Validate(ctx ActionCtx) error {
	if p.ASU == "" {
		return errors.New("no account server url was provided by the operator jwt or to nsc")
	}
	return p.validURL(p.ASU)
}

func (p *SyncCmdParams) PostURL(ac *jwt.AccountClaims) (string, error) {
	u, err := url.Parse(p.ASU)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, ac.Subject)
	return u.String(), nil
}

func (p *SyncCmdParams) Run(ctx ActionCtx) error {
	n := p.AccountContextParams.Name
	raw, err := ctx.StoreCtx().Store.Read(store.Accounts, n, store.JwtName(n))
	if err != nil {
		return err
	}
	c, err := jwt.DecodeAccountClaims(string(raw))
	if err != nil {
		return err
	}
	u, err := p.PostURL(c)
	if err != nil {
		return err
	}

	resp, err := http.Post(u, "application/text", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("error posting jwt %d: %s", resp.StatusCode, resp.Status)
	}

	// if the store is managed, this means that the account
	// is self-signed, and the update should expect a response
	// back - the response should include the JWT signed
	// by the operator.
	if ctx.StoreCtx().Store.IsManaged() {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_, err = jwt.DecodeAccountClaims(string(body))
		if err != nil {
			err = ctx.StoreCtx().Store.StoreClaim(raw)
		}
	}
	return err
}
