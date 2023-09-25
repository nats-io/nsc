/*
 * Copyright 2018-2023 The NATS Authors
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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createExpirationsCommand() *cobra.Command {
	var params ExpirationsParams
	var cmd = &cobra.Command{
		Short: "Create a new expiration report",
		Example: `expirations --skip --within 1w (reports entities that are expiring within on week)
expirations --json --within 3M (reports in JSON all entities marking those expiring within a month)
`,
		Use:  `expirations`,
		Args: MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = false
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.within, "within", "e", "1M", "print an expiration report for entities that expire within the specified duration.\nSupported are YYYY-MM-DD for absolute, and relative of now\n (m)inute, (h)our, (d)ay, (w)week, (M)onth, (y)ear expressions")
	cmd.Flags().BoolVarP(&params.json, "json", "", false, "print the expiration report in json format to stdout")
	cmd.Flags().BoolVarP(&params.skip, "skip", "", false, "skip reporting entities that are not expired or expiring soon")
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createExpirationsCommand())
}

type ExpirationsParams struct {
	within             string
	expirationDuration int64
	json               bool
	skip               bool
	expirationReport   []*ExpirationReport
}

type ExpirationReport struct {
	Resource       string `json:"resource"`
	ID             string `json:"id"`
	When           string `json:"when"`
	Expiry         int64  `json:"expiry"`
	ExpirationDate string `json:"expiration_date"`
	ExpiresSoon    bool   `json:"expires_soon"`
	Expired        bool   `json:"expired"`
}

func (p *ExpirationsParams) renderTable(ctx ActionCtx) error {
	table := tablewriter.CreateTable()
	table.AddTitle(fmt.Sprintf("Expiration Report (%s)", HumanizedDate(p.expirationDuration)))
	table.AddHeaders("Expired", "Resource", "Expiration")
	for _, v := range p.expirationReport {
		s := ""
		if v.Expired {
			s = "Yes"
		} else if v.ExpiresSoon {
			s = "Soon"
		} else {
			s = "No"
		}
		table.AddRow(s, v.Resource, fmt.Sprintf("%s - %s", time.Unix(v.Expiry, 0).Format(time.RFC3339), v.When))
	}
	ctx.CurrentCmd().Println(table.Render())
	return nil
}

type ExpirationReportJSON struct {
	ExpirationThreshold string              `json:"expiration_threshold"`
	Report              []*ExpirationReport `json:"report"`
}

func (p *ExpirationsParams) renderJSON(_ctx ActionCtx) error {
	r := ExpirationReportJSON{
		ExpirationThreshold: time.Unix(p.expirationDuration, 0).Format(time.RFC3339),
		Report:              p.expirationReport,
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func (p *ExpirationsParams) SetDefaults(ctx ActionCtx) error {
	p.expirationDuration = 0
	if p.within != "" {
		d, err := ParseExpiry(p.within)
		if err != nil {
			return err
		}
		p.expirationDuration = d
	}
	return nil
}

func (p *ExpirationsParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ExpirationsParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ExpirationsParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ExpirationsParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *ExpirationsParams) isExpired(expiry int64) bool {
	if expiry == 0 {
		return false
	}
	now := time.Now().UTC().Unix()
	return now > expiry
}

func (p *ExpirationsParams) expiresSoon(expiry int64) bool {
	if expiry == 0 {
		return false
	}
	return p.expirationDuration > 0 && p.expirationDuration > expiry
}

func (p *ExpirationsParams) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return nil, err
	}
	r := &ExpirationReport{Resource: oc.Name,
		ID:             oc.Subject,
		When:           "Never",
		Expiry:         oc.Expires,
		Expired:        p.isExpired(oc.Expires),
		ExpiresSoon:    p.expiresSoon(oc.Expires),
		ExpirationDate: "",
	}
	if oc.Expires > 0 {
		r.When = HumanizedDate(oc.Expires)
		r.ExpirationDate = time.Unix(oc.Expires, 0).Format(time.RFC3339)
	}
	p.expirationReport = append(p.expirationReport, r)

	accounts, err := ctx.StoreCtx().Store.ListSubContainers(store.Accounts)
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(a)
		if err != nil {
			if store.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		r = &ExpirationReport{
			ID:             ac.Subject,
			Resource:       fmt.Sprintf("%s/%s", oc.Name, ac.Name),
			When:           "Never",
			Expiry:         ac.Expires,
			Expired:        p.isExpired(ac.Expires),
			ExpiresSoon:    p.expiresSoon(ac.Expires),
			ExpirationDate: "",
		}
		if ac.Expires > 0 {
			r.When = HumanizedDate(ac.Expires)
			r.ExpirationDate = time.Unix(ac.Expires, 0).Format(time.RFC3339)
		}
		p.expirationReport = append(p.expirationReport, r)

		users, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, a, store.Users)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			uc, err := ctx.StoreCtx().Store.ReadUserClaim(a, u)
			if err != nil {
				return nil, err
			}
			r := &ExpirationReport{Resource: fmt.Sprintf("%s/%s/%s", oc.Name, ac.Name, uc.Name),
				ID:             uc.Subject,
				When:           "Never",
				Expiry:         uc.Expires,
				Expired:        p.isExpired(uc.Expires),
				ExpiresSoon:    p.expiresSoon(uc.Expires),
				ExpirationDate: "",
			}
			if uc.Expires > 0 {
				r.When = HumanizedDate(uc.Expires)
				r.ExpirationDate = time.Unix(uc.Expires, 0).Format(time.RFC3339)
			}

			p.expirationReport = append(p.expirationReport, r)

			fp := ctx.StoreCtx().KeyStore.CalcUserCredsPath(ac.Name, uc.Name)
			_, err = os.Stat(fp)
			if err != nil {
				if !os.IsNotExist(err) {
					return nil, err
				}
				continue
			}
			d, err := Read(fp)
			if err != nil {
				return nil, err
			}
			token, err := jwt.ParseDecoratedJWT(d)
			if err != nil {
				return nil, err
			}
			uc2, err := jwt.DecodeUserClaims(token)
			if err != nil {
				return nil, err
			}
			r = &ExpirationReport{
				Resource:       fp,
				ID:             uc2.Subject,
				When:           "Never",
				Expiry:         uc2.Expires,
				Expired:        p.isExpired(uc2.Expires),
				ExpiresSoon:    p.expiresSoon(uc2.Expires),
				ExpirationDate: "",
			}
			if uc2.Expires > 0 {
				r.When = HumanizedDate(uc2.Expires)
				r.ExpirationDate = time.Unix(uc2.Expires, 0).Format(time.RFC3339)
			}
			p.expirationReport = append(p.expirationReport, r)
		}
	}
	if p.skip {
		var filter []*ExpirationReport
		for _, v := range p.expirationReport {
			if v.Expired || v.ExpiresSoon {
				filter = append(filter, v)
			}
		}
		p.expirationReport = filter
	}

	if p.json {
		return nil, p.renderJSON(ctx)
	} else {
		return nil, p.renderTable(ctx)
	}
}
