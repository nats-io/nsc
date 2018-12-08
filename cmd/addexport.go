/*
 * Copyright 2018 The NATS Authors
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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createAddExportCmd() *cobra.Command {
	var params AddExportParams
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Add an export",
		Args:  MaxArgs(0),
		Example: `nsc add export -i
nsc add export --subject "a.b.c.>"
nsc add export --service --subject a.b
ncc add export --name myexport --subject a.b --service`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() {
				visibility := "public"
				if params.export.TokenReq {
					visibility = "private"
				}
				cmd.Printf("Success! - added %s %s export %q\n", visibility, params.export.Type, params.export.Name)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.export.Name, "name", "n", "", "export name")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")
	cmd.Flags().BoolVarP(&params.service, "service", "r", false, "export type service")
	cmd.Flags().BoolVarP(&params.private, "private", "p", false, "private export - requires an activation to access")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddExportCmd())
}

type AddExportParams struct {
	AccountContextParams
	claim   *jwt.AccountClaims
	export  jwt.Export
	private bool
	service bool
	SignerParams
	stream  bool
	subject string
}

func (p *AddExportParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)

	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	p.export.TokenReq = p.private
	p.export.Subject = jwt.Subject(p.subject)
	p.export.Type = jwt.Stream
	if p.service {
		p.export.Type = jwt.Service
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
	i, err := cli.PromptChoices("export type", p.export.Type.String(), choices)
	if err != nil {
		return err
	}
	if i == 0 {
		p.export.Type = jwt.Stream
	} else {
		p.export.Type = jwt.Service
	}

	p.subject, err = cli.Prompt("subject", p.subject, true, func(s string) error {
		p.export.Subject = jwt.Subject(s)
		var vr jwt.ValidationResults
		p.export.Validate(&vr)
		if len(vr.Issues) > 0 {
			return errors.New(vr.Issues[0].Description)
		}
		return nil
	})

	if p.export.Name == "" {
		p.export.Name = p.subject
	}
	p.export.Name, err = cli.Prompt("export name", p.export.Name, true, cli.LengthValidator(1))

	p.export.TokenReq, err = cli.PromptBoolean(fmt.Sprintf("private %s", p.export.Type.String()), p.export.TokenReq)

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
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

func (p *AddExportParams) PostInteractive(ctx ActionCtx) error {
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

	// add the new claim
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

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddExportParams) Run(ctx ActionCtx) error {
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
}
