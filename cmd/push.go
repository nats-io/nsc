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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createPushCmd() *cobra.Command {
	var params PushCmdParams
	var cmd = &cobra.Command{
		Short:   "Push an account jwt to an Account JWT Server",
		Example: "push",
		Use: `push (currentAccount)
push -a <accountName>
push -A (all accounts)
push -P
push -P -A (all accounts)`,
		Args: MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().BoolVarP(&params.allAccounts, "all", "A", false, "push all accounts under the current operator (exclusive of -a)")
	cmd.Flags().BoolVarP(&params.prune, "prune", "P", false, "prune all accounts not under the current operator (exclusive of -a). Only works with nats based resolver.")
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "push regardless of validation issues")
	cmd.Flags().StringVarP(&params.ASU, "account-jwt-server-url", "u", "", "set account jwt server url for nsc sync (only http/https/nats urls supported if updating with nsc) If a nats url is provided ")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createPushCmd())
}

type PushCmdParams struct {
	AccountContextParams
	ASU              string
	sysAccUser       string // when present use
	sysAcc           string
	sysAccUserJwtOpt nats.Option
	allAccounts      bool
	force            bool
	prune            bool
	targeted         []string

	accountList []string
}

func processResponse(report *store.Report, resp *nats.Msg) (bool, string, interface{}) {
	serverResp := map[string]interface{}{}
	if err := json.Unmarshal(resp.Data, &serverResp); err != nil {
		report.AddError("failed to parse response: %v data: %s", err, string(resp.Data))
	} else if srv, ok := serverResp["server"]; !ok {
		report.AddError("server responded without server info: %s", string(resp.Data))
	} else if srv, ok := srv.(map[string]interface{}); !ok {
		report.AddError("server responded with bad server info: %s", string(resp.Data))
	} else if error, hasErr := serverResp["error"]; hasErr {
		if error, ok := error.(map[string]interface{}); ok {
			report.AddError("server %s responded with error: %s", srv["name"], error["description"])
		} else {
			report.AddError("server %s responded with bad error: %v", srv["name"], error)
		}
	} else if data, ok := serverResp["data"]; !ok {
		report.AddError("server %s responded without data: %s", srv["name"], string(resp.Data))
	} else {
		return true, srv["name"].(string), data
	}
	return false, "", nil
}

func systemAccountUser(ctx ActionCtx, sysAccUserName string) (string, string, nats.Option, error) {
	if op, err := ctx.StoreCtx().Store.ReadOperatorClaim(); err != nil {
		return "", "", nil, err
	} else if accNames, err := friendlyNames(ctx.StoreCtx().Operator.Name); err != nil {
		return "", "", nil, err
	} else if sysAccName, ok := accNames[op.SystemAccount]; !ok {
		return "", "", nil, fmt.Errorf(`system account "%s" not found`, op.SystemAccount)
	} else {
		if sysAccUserName == "" {
			sysAccUserName = "sys"
		}
		if claim, err := ctx.StoreCtx().Store.ReadUserClaim(sysAccName, sysAccUserName); err != nil {
			return "", "", nil, err
		} else if kp, err := ctx.StoreCtx().KeyStore.GetKeyPair(claim.Subject); err != nil {
			return "", "", nil, err
		} else if theJWT, err := ctx.StoreCtx().Store.ReadRawUserClaim(sysAccName, sysAccUserName); err != nil {
			return "", "", nil, err
		} else {
			jwtCb := func() (string, error) {
				return string(theJWT), nil
			}
			signCb := func(nonce []byte) ([]byte, error) {
				return kp.Sign(nonce)
			}
			return sysAccName, sysAccUserName, nats.UserJWT(jwtCb, signCb), nil
		}
	}
}

func isHttpUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") ||
		strings.Contains(url, ",http://") || strings.Contains(url, ",https://")
}

func (p *PushCmdParams) SetDefaults(ctx ActionCtx) error {
	if p.allAccounts && p.Name != "" {
		return errors.New("specify only one of --account or --all-accounts")
	}

	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	if p.ASU == "" || !isHttpUrl(p.ASU) {
		op, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		if p.ASU == "" {
			p.ASU = op.AccountServerURL
		}
		if op.SystemAccount != "" && op.AccountServerURL == "" {
			if p.ASU == "" {
				p.ASU = strings.Join(op.OperatorServiceURLs, ",")
			}
			if p.sysAcc, p.sysAccUser, p.sysAccUserJwtOpt, err = systemAccountUser(ctx, ""); err != nil {
				return err
			}
		}
	}
	c := GetConfig()
	var err error
	if p.accountList, err = c.ListAccounts(); err != nil {
		return err
	}
	if len(p.accountList) == 0 {
		return fmt.Errorf("operator %q has no accounts", c.Operator)
	}
	if !p.allAccounts && !p.prune {
		found := false
		for _, v := range p.accountList {
			if v == p.Name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("account %q is not under operator %q - nsc env to check your env", p.Name, c.Operator)
		}
	}
	return nil
}

func (p *PushCmdParams) validURL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("url cannot be empty")
	}

	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	supported := []string{"http", "https", "nats"}

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

func (p *PushCmdParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if !p.allAccounts && !p.prune {
		if err = p.AccountContextParams.Edit(ctx); err != nil {
			return err
		}
	}
	if p.ASU, err = cli.Prompt("Account Server URL or nats-resolver enabled nats-server URL", p.ASU, cli.Val(p.validURL)); err != nil {
		return err
	}
	if p.sysAcc != "" && !isHttpUrl(p.ASU) {
		p.sysAccUser, err = ctx.StoreCtx().PickUser(p.sysAcc)
	}

	return err
}

func (p *PushCmdParams) Load(ctx ActionCtx) error {
	if !p.allAccounts && !p.prune {
		if err := p.AccountContextParams.Validate(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *PushCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *PushCmdParams) Validate(ctx ActionCtx) error {
	if p.ASU == "" {
		return errors.New("no account server url or nats-server url was provided by the operator jwt")
	}
	if p.sysAccUser == "" && p.prune {
		return errors.New("prune only works for nats based account resolver")
	}

	if err := p.validURL(p.ASU); err != nil {
		return err
	}

	if !p.force {
		oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}

		// validate the jwts don't have issues
		accounts, err := p.getSelectedAccounts()
		if err != nil {
			return err
		}

		for _, v := range accounts {
			raw, err := ctx.StoreCtx().Store.Read(store.Accounts, v, store.JwtName(v))
			if err != nil {
				return err
			}

			ac, err := jwt.DecodeAccountClaims(string(raw))
			if err != nil {
				return fmt.Errorf("unable to push account %q: %v", v, err)
			}
			var vr jwt.ValidationResults
			ac.Validate(&vr)
			for _, e := range vr.Issues {
				if e.Blocking || e.TimeCheck {
					return fmt.Errorf("unable to push account %q as it has validation issues: %v", v, e.Description)
				}
			}
			if !ctx.StoreCtx().Store.IsManaged() && !oc.DidSign(ac) {
				return fmt.Errorf("unable to push account %q as it is not signed by the operator %q", v, ctx.StoreCtx().Operator.Name)
			}
		}
	}

	return nil
}

func (p *PushCmdParams) getSelectedAccounts() ([]string, error) {
	if p.allAccounts {
		a, err := GetConfig().ListAccounts()
		if err != nil {
			return nil, err
		}
		return a, nil
	} else if !p.prune {
		return []string{p.AccountContextParams.Name}, nil
	}
	return []string{}, nil
}

func multiRequest(nc *nats.Conn, report *store.Report, operation string, subject string, reqData []byte, respHandler func(srv string, data interface{})) int {
	ib := nats.NewInbox()
	sub, err := nc.SubscribeSync(ib)
	if err != nil {
		report.AddError("failed to subscribe to response subject: %v", err)
		return 0
	}
	if err := nc.PublishRequest(subject, ib, reqData); err != nil {
		report.AddError("failed to %s: %v", operation, err)
		return 0
	}
	responses := 0
	now := time.Now()
	start := now
	end := start.Add(time.Second)
	for ; end.After(now); now = time.Now() { // try with decreasing timeout until we dont get responses
		if resp, err := sub.NextMsg(end.Sub(now)); err != nil {
			if err != nats.ErrTimeout || responses == 0 {
				report.AddError("failed to get response to %s: %v", operation, err)
			}
		} else if ok, srv, data := processResponse(report, resp); ok {
			respHandler(srv, data)
			responses++
			continue
		}
		break
	}
	return responses
}

func (p *PushCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	var err error
	p.targeted, err = p.getSelectedAccounts()
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	if p.sysAccUser == "" {
		for _, v := range p.targeted {
			sub := store.NewReport(store.OK, "push %s to account server", v)
			sub.Opt = store.DetailsOnErrorOrWarning
			r.Add(sub)
			ps, err := p.pushAccount(v, ctx)
			if ps != nil {
				sub.Add(store.HoistChildren(ps)...)
			}
			if err != nil {
				sub.AddError("failed to push account %q: %v", v, err)
			}
			if sub.OK() {
				sub.Label = fmt.Sprintf("pushed %q to account server", v)
			}
		}
	} else {
		sysAcc, sysAccUser, opt, err := systemAccountUser(ctx, p.sysAccUser)
		if err != nil {
			r.AddError("error obtaining system account user: %v", err)
			return r, nil
		}
		nc, err := nats.Connect(p.ASU, opt, nats.Name("nsc-client"))
		if err != nil {
			r.AddError("failed to connect: %v", err)
			return r, nil
		}
		defer nc.Close()
		if len(p.targeted) != 0 {
			sub := store.NewReport(store.OK, `push to nats-server "%s" using system account "%s" user "%s"`,
				p.ASU, sysAcc, sysAccUser)
			r.Add(sub)
			for _, v := range p.targeted {
				subAcc := store.NewReport(store.OK, "push %s to nats-server with nats account resolver", v)
				sub.Add(subAcc)
				if raw, err := ctx.StoreCtx().Store.Read(store.Accounts, v, store.JwtName(v)); err != nil {
					subAcc.AddError("failed to read account %q: %v", v, err)
				} else {
					resp := multiRequest(nc, subAcc, "push account", "$SYS.REQ.CLAIMS.UPDATE", raw,
						func(srv string, data interface{}) {
							if data, ok := data.(map[string]interface{}); ok {
								subAcc.AddOK("pushed %q to nats-server %s: %s", v, srv, data["message"])
							} else {
								subAcc.AddOK("pushed %q to nats-server %s: %v", v, srv, data)
							}
						})
					subAcc.AddOK("pushed to a total of %d nats-server", resp)
				}
			}
		}
		if p.prune {
			subPrune := store.NewReport(store.OK, "prune nats-server with nats account resolver")
			r.Add(subPrune)
			deleteList := make([]string, 0, 1024)
			mapping := make(map[string]string)
			for _, name := range p.accountList {
				if claim, err := ctx.StoreCtx().Store.ReadAccountClaim(name); err != nil {
					subPrune.AddError("prune failed to create mapping for %s: %v", name, err)
					return r, nil // this is a hard error, if we cant create a mapping because of it we'd end up deleting
				} else {
					mapping[claim.Subject] = name
				}
			}
			respList := multiRequest(nc, subPrune, "list accounts", "$SYS.REQ.CLAIMS.LIST", nil,
				func(srv string, d interface{}) {
					data := d.([]interface{})
					subAccPrune := store.NewReport(store.OK, "list %d accounts from nats-server %s", len(data), srv)
					subPrune.Add(subAccPrune)
					for _, acc := range data {
						acc := acc.(string)
						if name, ok := mapping[acc]; ok {
							subAccPrune.AddOK("account %s named %s exists", acc, name)
						} else {
							subAccPrune.AddOK("account %s only exists in server", acc)
							deleteList = append(deleteList, acc)
						}
					}
				})
			subPrune.AddOK("listed accounts from a total of %d nats-server", respList)
			if len(deleteList) == 0 {
				subPrune.AddOK("nothing to prune")
			} else {
				subPrune.AddOK("pruning %d accounts", len(deleteList))
				deleteMsg := []byte(strings.Join(deleteList, "\n"))
				respPrune := multiRequest(nc, subPrune, "prune accounts", "$SYS.REQ.CLAIMS.DELETE", deleteMsg,
					func(srv string, data interface{}) {
						if data, ok := data.(map[string]interface{}); ok {
							subPrune.AddOK("pruned nats-server %s: %s", srv, data["message"])
						} else {
							subPrune.AddOK("pruned nats-server %s: %v", srv, data)
						}
					})
				if respPrune < respList {
					subPrune.AddError("Fewer server responded to prune (%d) than to earlier list (%d)."+
						" Accounts may not be completely pruned.", respPrune, respList)
				} else if respPrune > respList {
					subPrune.AddError("More server responded to prune (%d) than to earlier list (%d)."+
						" Not every Account may have been included for pruning.", respPrune, respList)
				}
			}
		}
	}
	return r, nil
}

func (p *PushCmdParams) pushAccount(n string, ctx ActionCtx) (store.Status, error) {
	raw, err := ctx.StoreCtx().Store.Read(store.Accounts, n, store.JwtName(n))
	if err != nil {
		return nil, err
	}
	c, err := jwt.DecodeAccountClaims(string(raw))
	if err != nil {
		return nil, err
	}
	u, err := AccountJwtURLFromString(p.ASU, c.Subject)
	if err != nil {
		return nil, err
	}
	return store.PushAccount(u, raw)
}
