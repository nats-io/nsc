// Copyright 2023 The NATS Authors
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/nats-io/nsc/v2/home"
	"github.com/spf13/cobra"
)

func init() {
	generateCmd.AddCommand(createGenerateContext())
}

type GenerateContextParams struct {
	AccountContextParams
	user        string
	context     string
	creds       string
	operatorURL string
}

func createGenerateContext() *cobra.Command {
	var params GenerateContextParams
	cmd := &cobra.Command{
		Use:          "context",
		Short:        "Generate nats cli user context",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate context --account a --user u --context contextName`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.user, "user", "u", "", "user name")
	cmd.Flags().StringVarP(&params.context, "context", "", "", "context name")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func (p *GenerateContextParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	if p.user == "" && p.AccountContextParams.Name != "" {
		entries, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, p.AccountContextParams.Name, store.Users)
		if err != nil {
			return err
		}
		switch len(entries) {
		case 0:
			return fmt.Errorf("account %q has no users", p.AccountContextParams.Name)
		case 1:
			p.user = entries[0]
		}
	}

	return nil
}

func (p *GenerateContextParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *GenerateContextParams) Load(ctx ActionCtx) error {
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	if len(oc.OperatorServiceURLs) > 0 {
		p.operatorURL = oc.OperatorServiceURLs[0]
	}
	return nil
}

func (p *GenerateContextParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *GenerateContextParams) Validate(ctx ActionCtx) error {
	if p.context == "" {
		return fmt.Errorf("context name is required")
	}
	if strings.ContainsAny(p.context, "/\\") {
		return fmt.Errorf("context name cannot contain filepath separators")
	}
	if p.AccountContextParams.Name == "" {
		return fmt.Errorf("account is required")
	}
	if p.user == "" {
		return fmt.Errorf("user is required")
	}
	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.user)) {
		return fmt.Errorf("user %q not found in %q", p.user, p.AccountContextParams.Name)
	}
	p.creds = ctx.StoreCtx().KeyStore.CalcUserCredsPath(p.AccountContextParams.Name, p.user)
	if _, err := os.Stat(p.creds); err != nil {
		return fmt.Errorf("creds file %q - doesn't exist - nsc generate creds first", p.creds)
	}
	return nil
}

type cliContext struct {
	Nsc   string `json:"nsc,omitempty"`
	Url   string `json:"url,omitempty"`
	Creds string `json:"creds,omitempty"`
}

func (p *GenerateContextParams) Run(ctx ActionCtx) (store.Status, error) {
	var s store.Status
	natsCli := cliContext{}
	natsCli.Creds = p.creds
	natsCli.Nsc = fmt.Sprintf(`nsc://%s/%s/%s`, ctx.StoreCtx().Operator.Name, p.AccountContextParams.Name, p.user)
	natsCli.Url = p.operatorURL

	if err := os.MkdirAll(home.NatsCliContextDir(), 0755); err != nil {
		s = store.ErrorStatus("failed to create context dir %q: %v", home.NatsCliContextDir(), err)
		return s, nil
	}
	if !strings.HasSuffix(p.context, ".json") {
		p.context = fmt.Sprintf("%s.json", p.context)
	}
	fn := filepath.Join(home.NatsCliContextDir(), p.context)
	ctx.CurrentCmd().Println(fn)
	bytes, err := json.Marshal(natsCli)
	if err != nil {
		s = store.FromError(err)
		return s, nil
	}
	if err := Write(fn, bytes); err != nil {
		s = store.ErrorStatus("failed to write context file: %v", err)
		return s, nil
	}
	s = store.OKStatus("wrote nats cli context file to %#q", AbbrevHomePaths(fn))

	return s, nil
}
