// Copyright 2018-2023 The NATS Authors
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
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
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
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "push regardless of validation issues")
	cmd.Flags().StringVarP(&params.ASU, "account-jwt-server-url", "u", "", "set account jwt server url for nsc sync (only http/https/nats urls supported if updating with nsc) If a nats url is provided ")

	cmd.Flags().BoolVarP(&params.diff, "diff", "D", false, "diff accounts present in nsc env and nats-account-resolver. Mutually exclusive of account-removal/prune.")
	cmd.Flags().BoolVarP(&params.prune, "prune", "P", false, "prune all accounts not under the current operator. Only works with nats-resolver enabled nats-server. Mutually exclusive of account-removal/diff.")
	cmd.Flags().StringVarP(&params.removeAcc, "account-removal", "R", "", "remove specific account. Only works with nats-resolver enabled nats-server. Mutually exclusive of prune/diff.")
	cmd.Flags().StringVarP(&params.sysAcc, "system-account", "", "", "System account for use with nats-resolver enabled nats-server. (Default is system account specified by operator)")
	cmd.Flags().StringVarP(&params.sysAccUser, "system-user", "", "", "System account user for use with nats-resolver enabled nats-server. (Default to temporarily generated user)")
	cmd.Flags().IntVarP(&params.timeout, "timeout", "", 1, "timeout in seconds [1-60] to wait for responses from the server (only applicable to nats-resolver configurations, and applies per operation)")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createPushCmd())
}

type PushCmdParams struct {
	AccountContextParams
	ASU         string
	sysAccUser  string // when present use
	sysAcc      string
	allAccounts bool
	force       bool
	prune       bool
	diff        bool
	removeAcc   string
	targeted    []string
	timeout     int

	accountList []string
}

func processResponse(report *store.Report, resp *nats.Msg) (bool, string, interface{}) {
	// ServerInfo copied from nats-server, refresh as needed. Error and Data are mutually exclusive
	serverResp := struct {
		Server *struct {
			Name      string    `json:"name"`
			Host      string    `json:"host"`
			ID        string    `json:"id"`
			Cluster   string    `json:"cluster,omitempty"`
			Version   string    `json:"ver"`
			Seq       uint64    `json:"seq"`
			JetStream bool      `json:"jetstream"`
			Time      time.Time `json:"time"`
		} `json:"server"`
		Error *struct {
			Description string `json:"description"`
			Code        int    `json:"code"`
		} `json:"error"`
		Data interface{} `json:"data"`
	}{}
	if err := json.Unmarshal(resp.Data, &serverResp); err != nil {
		report.AddError("failed to parse response: %v data: %s", err, string(resp.Data))
	} else if srvName := serverResp.Server.Name; srvName == "" {
		report.AddError("server responded without server name in info: %s", string(resp.Data))
	} else if err := serverResp.Error; err != nil {
		report.AddError("server %s responded with error: %s", srvName, err.Description)
	} else if data := serverResp.Data; data == nil {
		report.AddError("server %s responded without data: %s", srvName, string(resp.Data))
	} else {
		return true, srvName, data
	}
	return false, "", nil
}

// when sysAccName or sysAccUserName are "" we will try to find a suitable user
func getSystemAccountUser(ctx ActionCtx, sysAccName, sysAccUserName, allowSub string, allowPubs ...string) (string, nats.Option, error) {
	op, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return "", nil, err
	} else if accNames, err := friendlyNames(ctx.StoreCtx().Operator.Name); err != nil {
		return "", nil, err
	} else if sysAccName == "" {
		if sysAccName = accNames[op.SystemAccount]; sysAccName == "" {
			return "", nil, fmt.Errorf(`system account "%s" not found`, op.SystemAccount)
		}
	}

	getOpt := func(theJWT string, kp nkeys.KeyPair) nats.Option {
		return nats.UserJWT(
			func() (string, error) {
				return theJWT, nil
			}, func(nonce []byte) ([]byte, error) {
				return kp.Sign(nonce)
			})
	}
	// Attempt to generate temporary user credentials and
	if sysAccUserName == "" {
		if keys, err := ctx.StoreCtx().GetAccountKeys(sysAccName); err == nil && len(keys) > 0 {
			key := ""
			if op.StrictSigningKeyUsage {
				// first key is the account key
				keys := keys[1:]
				if len(keys) > 0 {
					ac, err := ctx.StoreCtx().Store.ReadAccountClaim(sysAccName)
					if err != nil {
						return "", nil, err
					}
					for _, k := range keys {
						scope, ok := ac.SigningKeys.GetScope(k)
						// try to find a key that doesn't have a scope
						if scope == nil && ok {
							key = k
							break
						}
					}
					if key == "" {
						return "", nil, fmt.Errorf(`system account %q only has scoped signing keys, specify --system-user`, sysAccName)
					}
				} else {
					return "", nil, fmt.Errorf(`operator requires signing keys, system account %q doesn't have signing keys'`, sysAccName)
				}
			} else {
				key = keys[0]
			}
			sysAccKp, err := ctx.StoreCtx().KeyStore.GetKeyPair(key)
			if sysAccKp != nil && err == nil {
				defer sysAccKp.Wipe()
				tmpUsrKp, err := nkeys.CreateUser()
				if err == nil {
					tmpUsrPub, err := tmpUsrKp.PublicKey()
					if err == nil {
						tmpUsrClaim := jwt.NewUserClaims(tmpUsrPub)
						tmpUsrClaim.IssuerAccount = op.SystemAccount
						tmpUsrClaim.Expires = time.Now().Add(2 * time.Minute).Unix()
						tmpUsrClaim.Name = "nsc temporary push user"
						tmpUsrClaim.Pub.Allow.Add(allowPubs...)
						tmpUsrClaim.Sub.Allow.Add(allowSub)
						if theJWT, err := tmpUsrClaim.Encode(sysAccKp); err == nil {
							return sysAccName, getOpt(theJWT, tmpUsrKp), nil
						}
					}
				}
			}
		}
		// in case of not finding a key, default to searching for an existing user and key
	}
	users := []string{sysAccUserName}
	if sysAccUserName == "" {
		var err error
		if users, err = ctx.StoreCtx().Store.ListEntries(store.Accounts, sysAccName, store.Users); err != nil {
			return "", nil, err
		} else if len(users) == 0 {
			return "", nil, err
		}
	}
	for _, sysUser := range users {
		claim, err := ctx.StoreCtx().Store.ReadUserClaim(sysAccName, sysUser)
		if err != nil {
			continue
		}
		kp, _ := ctx.StoreCtx().KeyStore.GetKeyPair(claim.Subject)
		if kp == nil {
			kp, _ = ctx.StoreCtx().KeyStore.GetKeyPair(claim.IssuerAccount)
			if kp == nil {
				continue
			}
		}
		if theJWT, err := ctx.StoreCtx().Store.ReadRawUserClaim(sysAccName, sysUser); err != nil {
			continue
		} else {
			return sysAccName, getOpt(string(theJWT), kp), nil
		}
	}
	return "", nil, fmt.Errorf(`no system account user with corresponding nkey found`)
}

func (p *PushCmdParams) SetDefaults(ctx ActionCtx) error {
	if p.allAccounts && p.Name != "" {
		return errors.New("specify only one of --account or --all-accounts")
	}
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	if p.ASU == "" {
		if op, err := ctx.StoreCtx().Store.ReadOperatorClaim(); err != nil {
			return err
		} else {
			p.ASU = op.AccountServerURL
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
	if !p.allAccounts && !(p.prune || p.removeAcc != "" || p.diff) {
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
	supported := []string{"http", "https", "nats", "ws", "wss"}

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
	if IsResolverURL(p.ASU) {
		if p.sysAcc == "" {
			if p.sysAcc, err = PickAccount(ctx.StoreCtx(), p.sysAcc); err != nil {
				return err
			}
		}
		if p.sysAccUser == "" {
			p.sysAccUser, err = PickUser(ctx.StoreCtx(), p.sysAcc)
		}
	}
	return err
}

func (p *PushCmdParams) Load(ctx ActionCtx) error {
	if !p.allAccounts && !(p.prune || p.removeAcc != "" || p.diff) {
		if err := p.AccountContextParams.Validate(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *PushCmdParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *PushCmdParams) Validate(ctx ActionCtx) error {
	if p.timeout < 1 {
		p.timeout = 1
	}
	if p.timeout > 60 {
		p.timeout = 60
	}
	if p.ASU == "" {
		return errors.New("no account server url or nats-server url was provided by the operator jwt")
	}
	if !IsResolverURL(p.ASU) && p.prune {
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
	if p.removeAcc != "" {
		if p.prune || p.diff {
			return errors.New("--prune/--diff and --account-removal <account> are mutually exclusive")
		}
		if !nkeys.IsValidPublicAccountKey(p.removeAcc) {
			if acc, err := ctx.StoreCtx().Store.ReadAccountClaim(p.removeAcc); err != nil {
				return err
			} else {
				p.removeAcc = acc.Subject
			}
		}
	} else if p.prune && p.diff {
		return errors.New("--prune and --diff are mutually exclusive")
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
	} else if !(p.prune || p.removeAcc != "" || p.diff) {
		return []string{p.AccountContextParams.Name}, nil
	}
	return []string{}, nil
}

func multiRequest(nc *nats.Conn, timeout int, report *store.Report, operation string, subject string, reqData []byte, respHandler func(srv string, data interface{})) int {
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
	end := start.Add(time.Second * time.Duration(timeout))
	for ; end.After(now); now = time.Now() { // try with decreasing timeout until we dont get responses
		if resp, err := sub.NextMsg(end.Sub(now)); err != nil {
			if !errors.Is(err, nats.ErrTimeout) || responses == 0 {
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

func obtainRequestKey(ctx ActionCtx, subPrune *store.Report) (nkeys.KeyPair, error) {
	opc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		subPrune.AddError("Operator needed to prune (err:%v)", err)
		return nil, err
	}
	keys, err := ctx.StoreCtx().GetOperatorKeys()
	if err != nil {
		subPrune.AddError("Operator keys needed to prune (err:%v)", err)
		return nil, err
	}
	if opc.StrictSigningKeyUsage {
		if len(keys) > 1 {
			keys = keys[1:]
		} else {
			keys = []string{}
		}
	}
	for _, k := range keys {
		kp, err := ctx.StoreCtx().KeyStore.GetKeyPair(k)
		if err != nil {
			return nil, err
		}
		if kp != nil && !reflect.ValueOf(kp).IsNil() {
			return kp, nil
		}
	}

	// if we are here we don't have it - see if it was provided by the
	kp, err := ctx.StoreCtx().ResolveKey(KeyPathFlag, nkeys.PrefixByteOperator)
	if err != nil {
		return nil, err
	}
	if kp != nil && !reflect.ValueOf(kp).IsNil() {
		return kp, nil
	}
	return nil, errors.New("operator keys needed to prune: no operator keys were not found in the keystore")
}

func sendDeleteRequest(ctx ActionCtx, nc *nats.Conn, timeout int, report *store.Report, deleteList []string, expectedResponses int) {
	if len(deleteList) == 0 {
		report.AddOK("nothing to prune")
		return
	}
	okp, err := obtainRequestKey(ctx, report)
	if err != nil {
		report.AddError("Could not obtain Operator key to sign the delete request (err:%v)", err)
		return
	}
	defer okp.Wipe()

	opPk, err := okp.PublicKey()
	if err != nil {
		report.AddError("Error decoding the operator public key (err:%v)", err)
		return
	}

	claim := jwt.NewGenericClaims(opPk)
	claim.Data["accounts"] = deleteList
	pruneJwt, err := claim.Encode(okp)
	if err != nil {
		report.AddError("Could not encode delete request (err:%v)", err)
		return
	}
	respPrune := multiRequest(nc, timeout, report, "prune", "$SYS.REQ.CLAIMS.DELETE", []byte(pruneJwt), func(srv string, data interface{}) {
		if dataMap, ok := data.(map[string]interface{}); ok {
			report.AddOK("pruned nats-server %s: %s", srv, dataMap["message"])
		} else {
			report.AddOK("pruned nats-server %s: %v", srv, data)
		}
	})
	if expectedResponses > 0 {
		if respPrune < expectedResponses {
			report.AddError("Fewer server responded to 'prune' (%d) than to 'list' (%d)."+
				" Accounts may not be completely pruned.", respPrune, expectedResponses)
		} else if respPrune > expectedResponses {
			report.AddError("More servers responded to 'prune' (%d) than to 'list' (%d)."+
				" Not every Account may have been included for pruning.", respPrune, expectedResponses)
		}
	}
}

func createMapping(ctx ActionCtx, rep *store.Report, accountList []string) (map[string]string, error) {
	mapping := make(map[string]string)
	for _, name := range accountList {
		if claim, err := ctx.StoreCtx().Store.ReadAccountClaim(name); err != nil {
			if err.(*store.ResourceErr).Err != store.ErrNotExist {
				if nkeys.IsValidPublicAccountKey(name) {
					mapping[name] = name
					continue
				}
			}
			rep.AddError("prune failed to create mapping for %s: %v", name, err)
			return nil, err // this is a hard error, if we cant create a mapping because of it we'd end up deleting
		} else {
			mapping[claim.Subject] = name
		}
	}
	return mapping, nil
}

func listNonPresentAccounts(nc *nats.Conn, timeout int, report *store.Report, mapping map[string]string) (int, []string) {
	deleteList := make([]string, 0, 1024)
	responseCount := multiRequest(nc, timeout, report, "list accounts", "$SYS.REQ.CLAIMS.LIST", nil, func(srv string, d interface{}) {
		data := d.([]interface{})
		subAccPrune := store.NewReport(store.OK, "list %d accounts from nats-server %s", len(data), srv)
		report.Add(subAccPrune)
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
	report.AddOK("listed accounts from a total of %d nats-server", responseCount)
	return responseCount, deleteList
}

func (p *PushCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	var err error
	p.targeted, err = p.getSelectedAccounts()
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	if !IsResolverURL(p.ASU) {
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
		nats.NewInbox()
		sysAcc, opt, err := getSystemAccountUser(ctx, p.sysAcc, p.sysAccUser, nats.InboxPrefix+">",
			"$SYS.REQ.CLAIMS.LIST", "$SYS.REQ.CLAIMS.UPDATE", "$SYS.REQ.CLAIMS.DELETE")
		if err != nil {
			r.AddError("error obtaining system account user: %v", err)
			return r, nil
		}
		nc, err := nats.Connect(p.ASU, createDefaultToolOptions("nsc_push", ctx, opt)...)
		if err != nil {
			r.AddError("failed to connect: %v", err)
			return r, nil
		}
		defer nc.Close()
		if len(p.targeted) != 0 {
			sub := store.NewReport(store.OK, `push to nats-server "%s" using system account "%s"`,
				p.ASU, sysAcc)
			r.Add(sub)
			for _, v := range p.targeted {
				subAcc := store.NewReport(store.OK, "push %s to nats-server with nats account resolver", v)
				sub.Add(subAcc)
				if raw, err := ctx.StoreCtx().Store.Read(store.Accounts, v, store.JwtName(v)); err != nil {
					subAcc.AddError("failed to read account %q: %v", v, err)
				} else {
					resp := multiRequest(nc, p.timeout, subAcc, "push account", "$SYS.REQ.CLAIMS.UPDATE", raw, func(srv string, data interface{}) {
						if dataMap, ok := data.(map[string]interface{}); ok {
							subAcc.AddOK("pushed %q to nats-server %s: %s", v, srv, dataMap["message"])
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
			mapping, err := createMapping(ctx, subPrune, p.accountList)
			if err != nil {
				return r, nil
			}
			responseCount, deleteList := listNonPresentAccounts(nc, p.timeout, subPrune, mapping)
			sendDeleteRequest(ctx, nc, p.timeout, subPrune, deleteList, responseCount)
		} else if p.removeAcc != "" {
			subRemove := store.NewReport(store.OK, "prune nats-server with nats account resolver")
			r.Add(subRemove)
			sendDeleteRequest(ctx, nc, p.timeout, subRemove, []string{p.removeAcc}, -1)
		} else if p.diff {
			subDiff := store.NewReport(store.OK, "diff nats-server with nats account resolver")
			r.Add(subDiff)
			accList, err := GetConfig().ListAccounts()
			if err != nil {
				subDiff.AddError("diff could not obtain account list: %v", err)
				return r, nil
			}
			mapping, err := createMapping(ctx, subDiff, accList)
			if err != nil {
				subDiff.AddError("diff could not create account mapping: %v", err)
				return r, nil
			}

			listNonPresentAccounts(nc, p.timeout, subDiff, mapping)
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
