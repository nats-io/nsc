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
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createEditOperatorCmd() *cobra.Command {
	var params EditOperatorParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Edit the operator",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	params.signingKeys.BindFlags("sk", "", nkeys.PrefixByteOperator, cmd)
	cmd.Flags().StringSliceVarP(&params.rmSigningKeys, "rm-sk", "", nil, "remove signing key - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.asu, "account-jwt-server-url", "u", "", "set account jwt server url for nsc sync (only http/https urls supported if updating with nsc)")
	cmd.Flags().StringSliceVarP(&params.serviceURLs, "service-url", "n", nil, "add an operator service url for nsc where clients can access the NATS service (only nats/tls urls supported)")
	cmd.Flags().StringSliceVarP(&params.rmServiceURLs, "rm-service-url", "", nil, "remove an operator service url for nsc where clients can access the NATS service (only nats/tls urls supported)")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditOperatorCmd())
}

type EditOperatorParams struct {
	SignerParams
	GenericClaimsParams
	claim         *jwt.OperatorClaims
	token         string
	asu           string
	serviceURLs   []string
	rmServiceURLs []string
	signingKeys   SigningKeysParams
	rmSigningKeys []string
}

func (p *EditOperatorParams) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, false, ctx)

	if !InteractiveFlag && ctx.NothingToDo("sk", "rm-sk", "start", "expiry", "tag", "rm-tag", "account-jwt-server-url", "service-url", "rm-service-url") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditOperatorParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *EditOperatorParams) Load(ctx ActionCtx) error {
	var err error

	name := ctx.StoreCtx().Store.GetName()
	if !ctx.StoreCtx().Store.Has(store.JwtName(name)) {
		return fmt.Errorf("no operator %q found", name)
	}

	d, err := ctx.StoreCtx().Store.Read(store.JwtName(name))
	if err != nil {
		return err
	}

	oc, err := jwt.DecodeOperatorClaims(string(d))
	if err != nil {
		return err
	}

	if p.asu == "" {
		p.asu = oc.AccountServerURL
	}

	p.claim = oc
	return nil
}

func (p *EditOperatorParams) PostInteractive(ctx ActionCtx) error {
	var err error
	if p.claim.NotBefore > 0 {
		p.TimeParams.Start = UnixToDate(p.claim.NotBefore)
	}
	if p.claim.Expires > 0 {
		p.TimeParams.Expiry = UnixToDate(p.claim.Expires)
	}
	if err = p.GenericClaimsParams.Edit(p.claim.Tags); err != nil {
		return err
	}
	p.asu, err = cli.Prompt("account jwt server url", p.asu)
	if err != nil {
		return err
	}
	p.asu = strings.TrimSpace(p.asu)

	ok, err := cli.Confirm("add a service url", true)
	if err != nil {
		return err
	}
	if ok {
		for {
			v, err := cli.Prompt("operator service url", "", cli.Val(jwt.ValidateOperatorServiceURL))
			if err != nil {
				return err
			}
			// the list will prune empty urls
			p.serviceURLs = append(p.serviceURLs, v)
			ok, err := cli.Confirm("add another service url", true)
			if err != nil {
				return err
			}
			if !ok {
				break
			}
		}
	}
	if len(p.claim.OperatorServiceURLs) > 0 {
		ok, err = cli.Confirm("remove any service urls", true)
		if err != nil {
			return err
		}
		if ok {
			idx, err := cli.MultiSelect("select service urls to remove", p.claim.OperatorServiceURLs)
			if err != nil {
				return err
			}
			for _, v := range idx {
				p.rmServiceURLs = append(p.rmServiceURLs, p.claim.OperatorServiceURLs[v])
			}
		}
	}

	if err := p.signingKeys.Edit(); err != nil {
		return err
	}

	return p.SignerParams.Edit(ctx)
}

func (p *EditOperatorParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.GenericClaimsParams.Valid(); err != nil {
		return err
	}

	for _, v := range p.serviceURLs {
		if err := jwt.ValidateOperatorServiceURL(v); err != nil {
			return err
		}
	}

	if err = p.signingKeys.Valid(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditOperatorParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	r.ReportSum = false

	var err error
	if err = p.GenericClaimsParams.Run(ctx, p.claim, r); err != nil {
		return nil, err
	}
	keys, _ := p.signingKeys.PublicKeys()
	if len(keys) > 0 {
		p.claim.SigningKeys.Add(keys...)
		for _, k := range keys {
			r.AddOK("added signing key %q", k)
		}
	}
	p.claim.SigningKeys.Remove(p.rmSigningKeys...)
	for _, k := range p.rmSigningKeys {
		r.AddOK("removed signing key %q", k)
	}

	flags := ctx.CurrentCmd().Flags()
	p.claim.AccountServerURL = p.asu
	if flags.Changed("account-jwt-server-url") {
		r.AddOK("set account jwt server url to %q", p.asu)
	}

	for _, v := range p.serviceURLs {
		p.claim.OperatorServiceURLs.Add(strings.ToLower(v))
		r.AddOK("added service url %q", v)
	}
	for _, v := range p.rmServiceURLs {
		p.claim.OperatorServiceURLs.Remove(strings.ToLower(v))
		r.AddOK("removed service url %q", v)
	}

	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	s, err := ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
	if s != nil {
		r.Add(s)
	}
	if err != nil {
		r.AddFromError(err)
	}
	r.AddOK("edited operator %q", p.claim.Name)

	return r, nil
}
