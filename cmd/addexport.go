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
	"strconv"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddExportCmd() *cobra.Command {
	var params AddExportParams
	cmd := &cobra.Command{
		Use:          "export",
		Short:        "Add an export",
		Args:         MaxArgs(0),
		Example:      params.longHelp(),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.export.Name, "name", "n", "", "export name")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")
	cmd.Flags().BoolVarP(&params.service, "service", "r", false, "export type service")
	cmd.Flags().BoolVarP(&params.private, "private", "p", false, "private export - requires an activation to access")
	cmd.Flags().StringVarP(&params.latSubject, "latency", "", "", "latency metrics subject (services only)")
	cmd.Flags().IntVarP(&params.latSampling, "sampling", "", 0, "latency sampling percentage [1-100]  (services only)")
	hm := fmt.Sprintf("response type for the service [%s | %s | %s] (services only)", jwt.ResponseTypeSingleton, jwt.ResponseTypeStream, jwt.ResponseTypeChunked)
	cmd.Flags().StringVarP(&params.responseType, "response-type", "", jwt.ResponseTypeSingleton, hm)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddExportCmd())
}

type AddExportParams struct {
	AccountContextParams
	claim  *jwt.AccountClaims
	export jwt.Export

	private bool
	service bool
	SignerParams
	subject      string
	latSubject   string
	latSampling  int
	responseType string
}

func (p *AddExportParams) longHelp() string {
	s := `toolName add export -i
toolName add export --subject "a.b.c.>"
toolName add export --service --subject a.b
toolName add export --name myexport --subject a.b --service`
	return strings.Replace(s, "toolName", GetToolName(), -1)
}

func (p *AddExportParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	p.export.TokenReq = p.private
	p.export.Subject = jwt.Subject(p.subject)
	p.export.Type = jwt.Stream
	if p.service {
		p.export.Type = jwt.Service
		p.export.ResponseType = jwt.ResponseType(p.responseType)
	}

	if p.export.Name == "" {
		p.export.Name = p.subject
	}

	return nil
}

func (p *AddExportParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	choices := []string{jwt.Stream.String(), jwt.Service.String()}
	i, err := cli.Select("export type", p.export.Type.String(), choices)
	if err != nil {
		return err
	}
	if i == 0 {
		p.export.Type = jwt.Stream
	} else {
		p.export.Type = jwt.Service
	}

	svFn := func(s string) error {
		p.export.Subject = jwt.Subject(s)
		var vr jwt.ValidationResults
		p.export.Validate(&vr)
		if len(vr.Issues) > 0 {
			return errors.New(vr.Issues[0].Description)
		}
		return nil
	}

	p.subject, err = cli.Prompt("subject", p.subject, cli.Val(svFn))
	if err != nil {
		return err
	}
	p.export.Subject = jwt.Subject(p.subject)

	if p.export.Name == "" {
		p.export.Name = p.subject
	}

	p.export.Name, err = cli.Prompt("name", p.export.Name, cli.NewLengthValidator(1))
	if err != nil {
		return err
	}

	p.export.TokenReq, err = cli.Confirm(fmt.Sprintf("private %s", p.export.Type.String()), p.export.TokenReq)
	if err != nil {
		return err
	}

	if p.export.IsService() {
		ok, err := cli.Confirm("track service latency", false)
		if err != nil {
			return err
		}
		if ok {
			samp, err := cli.Prompt("sampling percentage [1-100]", "", cli.Val(SamplingValidator))
			if err != nil {
				return err
			}
			// cannot fail
			p.latSampling, _ = strconv.Atoi(samp)

			p.latSubject, err = cli.Prompt("latency metrics subject", "", cli.Val(LatencyMetricsSubjectValidator))
			if err != nil {
				return err
			}
		}

		choices := []string{jwt.ResponseTypeSingleton, jwt.ResponseTypeStream, jwt.ResponseTypeChunked}
		s, err := cli.Select("service response type", string(p.export.ResponseType), choices)
		if err != nil {
			return err
		}
		p.export.ResponseType = jwt.ResponseType(choices[s])
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func SamplingValidator(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	if v < 1 || v > 100 {
		return errors.New("sampling must be between 1 and 100 inclusive")
	}
	return nil
}

func LatencyMetricsSubjectValidator(s string) error {
	var lat jwt.ServiceLatency
	// bogus freq just to get a value into the validation
	lat.Sampling = 100
	lat.Results = jwt.Subject(s)
	var vr jwt.ValidationResults
	lat.Validate(&vr)
	if len(vr.Issues) > 0 {
		return errors.New(vr.Issues[0].Description)
	}
	return nil
}

func (p *AddExportParams) Load(ctx ActionCtx) error {
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

func (p *AddExportParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *AddExportParams) Validate(ctx ActionCtx) error {
	var err error
	if p.subject == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("a subject is required")
	}

	// get the old validation results
	var vr jwt.ValidationResults
	if err = p.claim.Exports.Validate(&vr); err != nil {
		return err
	}

	// if we have a latency report subject create it
	if p.latSubject != "" {
		p.export.Latency = &jwt.ServiceLatency{Results: jwt.Subject(p.latSubject), Sampling: p.latSampling}
	}

	// add the new export
	p.claim.Exports.Add(&p.export)

	var vr2 jwt.ValidationResults
	if err = p.claim.Exports.Validate(&vr2); err != nil {
		return err
	}

	// filter out all the old validations
	uvr := jwt.CreateValidationResults()
	if len(vr.Issues) > 0 {
		for _, nis := range vr.Issues {
			for _, is := range vr2.Issues {
				if nis.Description == is.Description {
					continue
				}
			}
			uvr.Add(nis)
		}
	} else {
		uvr = &vr2
	}
	// fail validation
	if len(uvr.Issues) > 0 {
		return errors.New(uvr.Issues[0].Error())
	}

	if p.service {
		rt := jwt.ResponseType(p.responseType)
		if rt != jwt.ResponseTypeSingleton &&
			rt != jwt.ResponseTypeStream &&
			rt != jwt.ResponseTypeChunked {
			return fmt.Errorf("unknown response type %q", p.responseType)
		}
		p.export.ResponseType = rt
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddExportParams) Run(ctx ActionCtx) (store.Status, error) {
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	visibility := "public"
	if p.export.TokenReq {
		visibility = "private"
	}
	r := store.NewDetailedReport(false)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		r.AddOK("added %s %s export %q", visibility, p.export.Type, p.export.Name)
	}
	return r, err
}
