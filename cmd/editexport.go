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

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createEditExportCmd() *cobra.Command {
	var params EditExportParams
	cmd := &cobra.Command{
		Use:          "export",
		Short:        "Edit an export",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "export name")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")
	cmd.Flags().BoolVarP(&params.service, "service", "r", false, "export type service")
	cmd.Flags().BoolVarP(&params.private, "private", "p", false, "private export - requires an activation to access")
	cmd.Flags().StringVarP(&params.latSubject, "latency", "", "", "latency metrics subject (services only)")
	cmd.Flags().IntVarP(&params.latSampling, "sampling", "", 0, "latency sampling percentage [0-100] - 0 disables it (services only)")
	cmd.Flags().BoolVarP(&params.rmLatencySampling, "rm-latency-sampling", "", false, "remove latency sampling")

	hm := fmt.Sprintf("response type for the service [%s | %s | %s] (services only)", jwt.ResponseTypeSingleton, jwt.ResponseTypeStream, jwt.ResponseTypeChunked)
	cmd.Flags().StringVarP(&params.responseType, "response-type", "", jwt.ResponseTypeSingleton, hm)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditExportCmd())
}

type EditExportParams struct {
	AccountContextParams
	SignerParams
	claim   *jwt.AccountClaims
	index   int
	subject string

	name              string
	latSampling       int
	latSubject        string
	service           bool
	private           bool
	responseType      string
	rmLatencySampling bool
}

func (p *EditExportParams) SetDefaults(ctx ActionCtx) error {
	if !InteractiveFlag {
		if ctx.NothingToDo("name", "subject", "service", "private", "latency", "sampling", "response-type") {
			return errors.New("please specify some options")
		}
	}
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	p.index = -1
	return nil
}

func (p *EditExportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditExportParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	switch len(p.claim.Exports) {
	case 0:
		return fmt.Errorf("account %q doesn't have exports", p.AccountContextParams.Name)
	case 1:
		if p.subject == "" {
			p.subject = string(p.claim.Exports[0].Subject)
		}
	}

	for i, e := range p.claim.Exports {
		if string(e.Subject) == p.subject {
			p.index = i
			break
		}
	}

	// if we are not running in interactive set the option default the non-set values
	if !InteractiveFlag {
		p.syncOptions(ctx)
	}

	return nil
}

func (p *EditExportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	choices, err := GetAccountExports(p.claim)
	if err != nil {
		return err
	}
	labels := AccountExportChoices(choices).String()
	index := p.index
	if index == -1 {
		index = 0
	}
	p.index, err = cli.Select("select export to edit", labels[index], labels)
	if err != nil {
		return err
	}

	sel := choices[p.index].Selection

	kinds := []string{jwt.Stream.String(), jwt.Service.String()}
	k := kinds[0]
	if sel.Type == jwt.Service {
		k = kinds[1]
	}
	i, err := cli.Select("export type", k, kinds)
	if err != nil {
		return err
	}
	p.service = i == 1

	svFn := func(s string) error {
		var export jwt.Export
		export.Type = jwt.Stream
		if p.service {
			export.Type = jwt.Service
		}
		export.Subject = jwt.Subject(s)
		var vr jwt.ValidationResults
		export.Validate(&vr)
		if len(vr.Issues) > 0 {
			return errors.New(vr.Issues[0].Description)
		}
		return nil
	}

	p.subject, err = cli.Prompt("subject", string(sel.Subject), cli.Val(svFn))
	if err != nil {
		return err
	}

	if p.name == "" {
		p.name = sel.Name
	}
	p.name, err = cli.Prompt("name", p.name, cli.NewLengthValidator(1))
	if err != nil {
		return err
	}

	p.private, err = cli.Confirm(fmt.Sprintf("private %s", k), sel.TokenReq)
	if err != nil {
		return err
	}

	if p.service {
		ok, err := cli.Confirm("track service latency", false)
		if err != nil {
			return err
		}
		if ok {
			cls := 0
			results := jwt.Subject("")
			if sel.Latency != nil {
				cls = sel.Latency.Sampling
				results = sel.Latency.Results
			}
			samp, err := cli.Prompt("sampling percentage [1-100]", fmt.Sprintf("%d", cls), cli.Val(SamplingValidator))
			if err != nil {
				return err
			}
			// cannot fail
			p.latSampling, _ = strconv.Atoi(samp)

			p.latSubject, err = cli.Prompt("latency metrics subject", string(results), cli.Val(LatencyMetricsSubjectValidator))
			if err != nil {
				return err
			}
		} else {
			p.rmLatencySampling = true
		}

		choices := []string{jwt.ResponseTypeSingleton, jwt.ResponseTypeStream, jwt.ResponseTypeChunked}
		s, err := cli.Select("service response type", p.responseType, choices)
		if err != nil {
			return err
		}
		p.responseType = choices[s]
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *EditExportParams) Validate(ctx ActionCtx) error {
	ctx.CurrentCmd().SilenceUsage = false
	var err error
	if p.subject == "" {
		return errors.New("a subject is required")
	}
	if p.index == -1 {
		return fmt.Errorf("no export with subject %q found", p.subject)
	}

	if p.service {
		rt := jwt.ResponseType(p.responseType)
		if rt != jwt.ResponseTypeSingleton &&
			rt != jwt.ResponseTypeStream &&
			rt != jwt.ResponseTypeChunked {
			return fmt.Errorf("unknown response type %q", p.responseType)
		}
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *EditExportParams) syncOptions(ctx ActionCtx) {
	if p.index == -1 {
		return
	}
	old := *p.claim.Exports[p.index]

	cmd := ctx.CurrentCmd()
	if !cmd.Flag("service").Changed {
		p.service = old.Type == jwt.Service
	}
	if !cmd.Flag("response-type").Changed {
		if old.ResponseType == "" {
			old.ResponseType = jwt.ResponseTypeSingleton
		}
		p.responseType = string(old.ResponseType)
	}
	if !(cmd.Flag("name").Changed) {
		p.name = old.Name
	}
	if !(cmd.Flag("private").Changed) {
		p.private = old.TokenReq
	}
	sampling := 0
	latency := ""
	if old.Latency != nil {
		sampling = old.Latency.Sampling
		latency = string(old.Latency.Results)
	}
	if !(cmd.Flag("latency").Changed) {
		p.latSubject = latency
	}
	if !(cmd.Flag("sampling").Changed) {
		p.latSampling = sampling
	}

	if !(cmd.Flag("response-type").Changed) {
		p.responseType = string(old.ResponseType)
	}

}

func (p *EditExportParams) Run(ctx ActionCtx) (store.Status, error) {
	old := *p.claim.Exports[p.index]
	// old vr
	var vr jwt.ValidationResults
	if err := p.claim.Exports.Validate(&vr); err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(false)
	var export jwt.Export
	export.Name = p.name
	if export.Name != old.Name {
		r.AddOK("changed export name to %s", export.Name)
	}

	export.TokenReq = p.private
	if export.TokenReq != old.TokenReq {
		r.AddWarning("changed export to be private - this will break importers")
	}
	export.Subject = jwt.Subject(p.subject)
	if export.Subject != old.Subject {
		r.AddWarning("changed subject to %q - this will break importers", export.Subject)
	}
	export.Type = jwt.Stream
	if p.service {
		export.Type = jwt.Service
	}
	if export.Type != old.Type {
		r.AddWarning("changed export type to %q - this will break importers", export.Type.String())
	}

	if export.Type == jwt.Service {
		// old response type may be blank
		if old.ResponseType == "" {
			old.ResponseType = jwt.ResponseTypeSingleton
		}

		if p.rmLatencySampling {
			export.Latency = nil
			if old.Latency != nil {
				r.AddOK("removed latency tracking")
			} else {
				r.AddOK("no need to remove latency tracking as it was not set")
			}
		} else {
			oldSampling := 0
			oldReport := jwt.Subject("")
			if old.Latency != nil {
				oldSampling = old.Latency.Sampling
				oldReport = old.Latency.Results
			}
			if p.latSubject != "" {
				export.Latency = &jwt.ServiceLatency{Results: jwt.Subject(p.latSubject), Sampling: p.latSampling}
				if oldSampling != export.Latency.Sampling {
					r.AddOK("changed service latency to %d%%", export.Latency.Sampling)
				}
				if oldReport != "" && oldReport != export.Latency.Results {
					r.AddOK("changed service latency subject to %s", export.Latency.Results)
					r.AddWarning("changed latency subject will break consumers of the report")
				}
			}
		}

		rt := jwt.ResponseType(p.responseType)
		if old.ResponseType != rt {
			export.ResponseType = rt
			r.AddOK("changed response type to %s", p.responseType)
		}
	}

	p.claim.Exports[p.index] = &export

	var vr2 jwt.ValidationResults
	if err := p.claim.Exports.Validate(&vr2); err != nil {
		return nil, err
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
		return nil, errors.New(uvr.Issues[0].Error())
	}

	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		r.AddOK("edited %s export %q", export.Type, export.Name)
	}
	return r, err
}
