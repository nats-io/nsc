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
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/nats-io/nsc/cmd/store"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/spf13/cobra"
)

func createPullCmd() *cobra.Command {
	var params PullParams
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull an operator or account jwt replacing the local jwt with the server's version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}

	cmd.Flags().BoolVarP(&params.All, "all", "A", false, "operator and all accounts under the operator")
	cmd.Flags().BoolVarP(&params.Overwrite, "overwrite-newer", "F", false, "overwrite local JWTs that are newer than remote")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	rootCmd.AddCommand(createPullCmd())
}

type PullParams struct {
	AccountContextParams
	All       bool
	Jobs      PullJobs
	Overwrite bool
}

type PullJob struct {
	Name       string
	ASU        string
	Err        error
	StoreErr   error
	LocalClaim jwt.Claims

	PullStatus *store.Report
}

func (j *PullJob) Token() (string, error) {
	if len(j.PullStatus.Data) == 0 {
		return "", errors.New("no data")
	}
	token, err := jwt.ParseDecoratedJWT(j.PullStatus.Data)
	if err != nil {
		return "", err
	}
	j.PullStatus.Data = []byte(token)
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return "", err
	}
	switch gc.Type {
	case jwt.AccountClaim:
		_, err := jwt.DecodeAccountClaims(token)
		if err != nil {
			return "", err
		}
		return token, nil
	case jwt.OperatorClaim:
		_, err := jwt.DecodeOperatorClaims(token)
		if err != nil {
			return "", err
		}
		return token, nil
	default:
		return "", fmt.Errorf("unsupported token type: %q", gc.Type)
	}
}

func (j *PullJob) Run() {
	s, err := store.PullAccount(j.ASU)
	if err != nil {
		j.Err = err
		return
	}
	ps, ok := s.(*store.Report)
	if !ok {
		j.Err = errors.New("unable to convert pull status")
		return
	}
	j.PullStatus = ps
}

type PullJobs []*PullJob

func (p *PullParams) SetDefaults(ctx ActionCtx) error {
	return p.AccountContextParams.SetDefaults(ctx)
}

func (p *PullParams) PreInteractive(ctx ActionCtx) error {
	var err error
	tc := GetConfig()
	p.All, err = cli.Confirm(fmt.Sprintf("pull operator %q and all accounts", tc.Operator), true)
	if err != nil {
		return err
	}
	if !p.All {
		if err := p.AccountContextParams.Edit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *PullParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *PullParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *PullParams) Validate(ctx ActionCtx) error {
	if !p.All && p.Name == "" {
		return errors.New("specify --all or --account")
	}
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	if oc.AccountServerURL == "" && len(oc.OperatorServiceURLs) == 0 {
		return fmt.Errorf("operator %q doesn't set account server url or operator service url - unable to pull", ctx.StoreCtx().Operator.Name)
	}
	if oc.AccountServerURL == "" && len(oc.OperatorServiceURLs) > 0 && !p.All {
		return fmt.Errorf("operator %q can only pull all jwt - unable to pull by account", ctx.StoreCtx().Operator.Name)
	}
	return nil
}

func (p *PullParams) setupJobs(ctx ActionCtx) error {
	s := ctx.StoreCtx().Store
	oc, err := s.ReadOperatorClaim()
	if err != nil {
		return err
	}
	if p.All {
		u, err := OperatorJwtURL(oc)
		if err != nil {
			return err
		}
		j := PullJob{ASU: u, Name: oc.Name, LocalClaim: oc}
		p.Jobs = append(p.Jobs, &j)

		tc := GetConfig()
		accounts, err := tc.ListAccounts()
		if err != nil {
			return err
		}
		for _, v := range accounts {
			ac, err := s.ReadAccountClaim(v)
			if err != nil {
				return err
			}
			u, err := AccountJwtURL(oc, ac)
			if err != nil {
				return err
			}
			j := PullJob{ASU: u, Name: ac.Name, LocalClaim: ac}
			p.Jobs = append(p.Jobs, &j)
		}
	} else {
		ac, err := s.ReadAccountClaim(p.Name)
		if err != nil {
			return err
		}
		u, err := AccountJwtURL(oc, ac)
		if err != nil {
			return err
		}
		j := PullJob{ASU: u, Name: ac.Name, LocalClaim: ac}
		p.Jobs = append(p.Jobs, &j)
	}

	return nil
}

func (p *PullParams) storeJwtIf(ctx ActionCtx, sub *store.Report, token string) {
	remoteClaim, err := jwt.DecodeGeneric(token)
	if err != nil {
		sub.AddError("error decoding remote token: %v %s", err, token)
		return
	}
	orig := int64(0)
	if localClaim, err := ctx.StoreCtx().Store.ReadAccountClaim(remoteClaim.Name); err == nil {
		orig = localClaim.IssuedAt
	}
	remote := remoteClaim.IssuedAt
	if (orig > remote) && !p.Overwrite {
		sub.AddError("local jwt for %q is newer than remote version - specify --force to overwrite", remoteClaim.Name)
		return
	}
	if err := ctx.StoreCtx().Store.StoreRaw([]byte(token)); err != nil {
		sub.AddError("error storing %q: %v", remoteClaim.Name, err)
		return
	}
	sub.AddOK("stored %s %q", remoteClaim.Type, remoteClaim.Name)
	if sub.OK() {
		sub.Label = fmt.Sprintf("pulled %q from the account server", remoteClaim.Name)
	}
}

func (p *PullParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	if op, err := ctx.StoreCtx().Store.ReadOperatorClaim(); err != nil {
		r.AddError("could not read operator claim: %v", err)
		return r, err
	} else if op.AccountServerURL == "" && op.SystemAccount != "" && len(op.OperatorServiceURLs) != 0 {
		subR := store.NewReport(store.OK, `pull from cluster using system account`)
		r.Add(subR)
		_, _, opt, err := systemAccountUser(ctx, "")
		if err != nil {
			subR.AddError("failed to obtain system user: %v", err)
			return r, nil
		}
		url := strings.Join(op.OperatorServiceURLs, ",")
		nc, err := nats.Connect(url, opt, nats.Name("nsc-client"))
		if err != nil {
			subR.AddError("failed to connect to %s: %v", url, err)
			return r, nil
		}
		defer nc.Close()
		ib := nats.NewInbox()
		sub, err := nc.SubscribeSync(ib)
		if err != nil {
			subR.AddError("failed to subscribe to response subject: %v", err)
			return r, nil
		}
		if err := nc.PublishRequest("$SYS.REQ.CLAIMS.PACK", ib, nil); err != nil {
			subR.AddError("failed to pull accounts: %v", err)
			return r, nil
		}
		for {
			if resp, err := sub.NextMsg(time.Second); err != nil {
				subR.AddError("failed to get response to pull: %v", err)
				break
			} else if msg := string(resp.Data); msg == "" { // empty response means end
				break
			} else if tk := strings.Split(string(resp.Data), "|"); len(tk) != 2 {
				subR.AddError("pull response bad")
				break
			} else {
				p.storeJwtIf(ctx, subR, tk[1])
			}
		}
		return r, nil
	}

	ctx.CurrentCmd().SilenceUsage = true
	if err := p.setupJobs(ctx); err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	wg.Add(len(p.Jobs))
	for _, j := range p.Jobs {
		go func(j *PullJob) {
			defer wg.Done()
			j.Run()
		}(j)
	}
	wg.Wait()

	for _, j := range p.Jobs {
		sub := store.NewReport(store.OK, "pull %q from the account server", j.Name)
		sub.Opt = store.DetailsOnErrorOrWarning
		r.Add(sub)
		if j.PullStatus != nil {
			sub.Add(store.HoistChildren(j.PullStatus)...)
		}
		if j.Err != nil {
			sub.AddFromError(j.Err)
			continue
		}
		if j.PullStatus.OK() {
			token, _ := j.Token()
			p.storeJwtIf(ctx, sub, token)
		}
	}
	return r, nil
}
