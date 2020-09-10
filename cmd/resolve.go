/*
 * Copyright 2018-2020 The NATS Authors
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
	"os"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"

	"github.com/spf13/cobra"
)

func createResolveCmd() *cobra.Command {
	var params ResolveCmdParams
	var cmd = &cobra.Command{
		Use:     "resolve",
		Short:   "Resolve an nsc URL into a JSON blob that can be used by tooling",
		Example: "resolve nsc://<operator>/?<account>/?<user>",
		Args:    MaxArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			us := args[0]
			u, err := ParseNscURL(us)
			if err != nil {
				return fmt.Errorf("error parsing %q:%v", us, err)
			}
			params.nscu = u
			q := u.query()
			if len(q) > 0 {
				config := GetConfig()
				oldSR := config.StoreRoot
				oldOp := config.Operator
				oldAc := config.Account
				v, ok := q["store"]
				if ok {
					defer func() {
						config.setStoreRoot(oldSR)
						if oldOp != "" {
							config.SetOperator(oldOp)
						}
						if oldAc != "" {
							config.SetAccount(oldAc)
						}
					}()
					sr, err := Expand(v)
					if err != nil {
						return err
					}
					config.setStoreRoot(sr)
					config.SetOperator(u.operator)
				}

				storeDir, ok := q["keystore"]
				if ok {
					ks, err := Expand(storeDir)
					if err != nil {
						return err
					}
					os.Setenv(store.NKeysPathEnv, ks)
				}
			}
			return RunAction(cmd, args, &params)
		},
		Hidden: true,
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	return cmd
}

func init() {
	GetRootCmd().AddCommand(createResolveCmd())
}

type ResolveCmdParams struct {
	nscu       *NscURL
	results    *ResolveResults
	oc         *jwt.OperatorClaims
	ac         *jwt.AccountClaims
	uc         *jwt.UserClaims
	outputFile string
}

type Details struct {
	Service []string `json:"service,omitempty"`
	Name    string   `json:"name,omitempty"`
	Seed    string   `json:"seed,omitempty"`
	Key     string   `json:"id,omitempty"`
}

type ResolveResults struct {
	UserCreds string   `json:"user_creds,omitempty"`
	Operator  *Details `json:"operator,omitempty"`
	Account   *Details `json:"account,omitempty"`
	User      *Details `json:"user,omitempty"`
}

type NscURL struct {
	operator string
	account  string
	user     string
	qs       string
}

func (u *NscURL) getOperator() (string, error) {
	return url.QueryUnescape(u.operator)
}

func (u *NscURL) getAccount() (string, error) {
	return url.QueryUnescape(u.account)
}

func (u *NscURL) getUser() (string, error) {
	return url.QueryUnescape(u.user)
}

func (u *NscURL) query() map[string]string {
	q := strings.ToLower(u.qs)
	m := make(map[string]string)
	for _, e := range strings.Split(q, "&") {
		kv := strings.Split(e, "=")
		k := kv[0]
		v := ""
		if len(kv) == 2 {
			v = kv[1]
		}
		m[k] = v
	}
	return m
}

func ParseNscURL(u string) (*NscURL, error) {
	var v NscURL
	s := u
	const prefix = "nsc://"
	if !strings.HasPrefix(strings.ToLower(u), prefix) {
		return nil, errors.New("invalid nsc url: expecting 'nsc://'")
	}
	s = s[len(prefix):]

	qs := strings.Index(s, "?")
	if qs > 0 {
		v.qs = s[qs+1:]
		s = s[:qs]
	}
	if s == "" {
		return nil, errors.New("invalid nsc url: expecting an operator name")
	}
	a := strings.Split(s, "/")
	if len(a) >= 1 {
		v.operator = a[0]
	}
	if len(a) >= 2 {
		v.account = a[1]
	}
	if len(a) >= 3 {
		v.user = a[2]
	}
	return &v, nil
}

func (p *ResolveCmdParams) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *ResolveCmdParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ResolveCmdParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ResolveCmdParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ResolveCmdParams) hasName(name string, names []string) bool {
	nn := strings.ToLower(name)
	for _, n := range names {
		if strings.ToLower(n) == nn {
			return true
		}
	}
	return false
}

func (p *ResolveCmdParams) loadNames(c jwt.Claims) []string {
	var names []string
	cd := c.Claims()
	names = append(names, cd.Name)
	names = append(names, cd.Subject)

	conf := GetConfig()
	payload := c.Payload()
	_, ok := payload.(jwt.Operator)
	if ok && conf.Operator != "" {
		names = append(names, conf.Operator)
	}
	return names
}

func (p *ResolveCmdParams) checkLoadOperator(ctx ActionCtx) error {
	conf := GetConfig()
	if conf.Operator == "" {
		return errors.New("no operator set - `env --operator <name>`")
	}

	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	names := p.loadNames(oc)
	names = append(names, conf.Operator)

	if !p.hasName(p.nscu.operator, names) {
		return fmt.Errorf("invalid operator %q: make sure you have the right operator context", p.nscu.operator)
	}
	p.nscu.operator = oc.Name
	p.oc = oc
	return nil
}

func (p *ResolveCmdParams) checkLoadAccount(ctx ActionCtx) error {
	if p.nscu.account == "" {
		return nil
	}
	config := GetConfig()
	names, err := config.ListAccounts()
	if err != nil {
		return err
	}

	m := make(map[string]string)
	for _, n := range names {
		m[strings.ToLower(n)] = n
	}
	an := m[strings.ToLower(p.nscu.account)]
	if an != "" {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(an)
		if err != nil {
			return err
		}
		p.nscu.account = ac.Name
		p.ac = ac
		return nil
	}

	for _, n := range names {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(n)
		if err != nil {
			return err
		}
		aliases := p.loadNames(ac)
		if p.hasName(p.nscu.account, aliases) {
			p.nscu.account = ac.Name
			p.ac = ac
			return nil
		}
	}
	return fmt.Errorf("invalid account %q: account was not found", p.nscu.account)
}

func (p *ResolveCmdParams) checkLoadUser(ctx ActionCtx) error {
	if p.nscu.user == "" {
		return nil
	}
	names, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, p.nscu.account, store.Users)
	if err != nil {
		return err
	}

	m := make(map[string]string)
	for _, n := range names {
		m[strings.ToLower(n)] = n
	}
	un := m[strings.ToLower(p.nscu.user)]
	if un != "" {
		uc, err := ctx.StoreCtx().Store.ReadUserClaim(p.nscu.account, un)
		if err != nil {
			return err
		}
		p.nscu.user = uc.Name
		p.uc = uc
		return nil
	}

	for _, n := range names {
		uc, err := ctx.StoreCtx().Store.ReadUserClaim(p.nscu.account, n)
		if err != nil {
			return err
		}
		aliases := p.loadNames(uc)
		if p.hasName(p.nscu.user, aliases) {
			p.nscu.user = uc.Name
			p.uc = uc
			return nil
		}
	}
	return fmt.Errorf("invalid user %q: user was not found", p.nscu.user)
}

func (p *ResolveCmdParams) Validate(ctx ActionCtx) error {
	err := p.checkLoadOperator(ctx)
	if err != nil {
		return err
	}
	err = p.checkLoadAccount(ctx)
	if err != nil {
		return err
	}
	err = p.checkLoadUser(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (p *ResolveCmdParams) addOperatorKeys() {
	p.results.Operator.Key = p.oc.Subject
}

func (p *ResolveCmdParams) addAccountKeys() {
	if p.results.Account == nil {
		p.results.Account = &Details{}
	}
	p.results.Account.Key = p.ac.Subject
}

func (p *ResolveCmdParams) addUserKeys() {
	if p.results.User == nil {
		p.results.User = &Details{}
	}
	p.results.User.Key = p.uc.Subject
}

func (p *ResolveCmdParams) addKeys() {
	q := p.nscu.query()
	if len(q) == 0 {
		return
	}
	_, ok := q["operatorkey"]
	if ok {
		p.addOperatorKeys()
	}
	_, ok = q["accountkey"]
	if ok {
		p.addAccountKeys()
	}
	_, ok = q["userkey"]
	if ok {
		p.addUserKeys()
	}
	_, ok = q["key"]
	if ok {
		if p.nscu.user != "" {
			p.addUserKeys()
		} else if p.nscu.account != "" {
			p.addAccountKeys()
		} else {
			p.addOperatorKeys()
		}
	}
}

func (p *ResolveCmdParams) getKeys(claim jwt.Claims) []string {
	var keys []string
	if claim != nil {
		keys = append(keys, claim.Claims().Subject)
		var payload = claim.Payload()
		oc, ok := payload.(jwt.Operator)
		if ok {
			keys = append(keys, oc.SigningKeys...)
		}
		ac, ok := payload.(jwt.Account)
		if ok {
			keys = append(keys, ac.SigningKeys...)
		}
	}
	return keys
}

func (p *ResolveCmdParams) resolveSeed(ctx ActionCtx, s string, keys []string) (string, error) {
	ks := ctx.StoreCtx().KeyStore
	if s != "" {
		found := false
		s = strings.ToUpper(s)
		for _, k := range keys {
			if s == k {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("%q was not found", s)
		}
		if ks.HasPrivateKey(s) {
			seed, err := ks.GetSeed(s)
			if seed != "" && err == nil {
				return seed, err
			}
		} else {
			return "", fmt.Errorf("no seed was found for %q", keys[0])
		}
	}
	for _, v := range keys {
		if ks.HasPrivateKey(v) {
			seed, err := ks.GetSeed(v)
			if seed != "" && err == nil {
				return seed, err
			}
		}
	}
	return "", fmt.Errorf("no seed was found for %q", keys[0])
}

func (p *ResolveCmdParams) addOperatorSeed(ctx ActionCtx, v string) error {
	seed, err := p.resolveSeed(ctx, v, p.getKeys(p.oc))
	if err != nil {
		return err
	}
	p.results.Operator.Seed = seed
	return nil
}

func (p *ResolveCmdParams) addAccountSeed(ctx ActionCtx, v string) error {
	seed, err := p.resolveSeed(ctx, v, p.getKeys(p.ac))
	if err != nil {
		return err
	}
	if p.results.Account == nil {
		p.results.Account = &Details{}
	}
	p.results.Account.Seed = seed
	return nil
}

func (p *ResolveCmdParams) addUserSeed(ctx ActionCtx, v string) error {
	seed, err := p.resolveSeed(ctx, v, p.getKeys(p.uc))
	if err != nil {
		return err
	}
	if p.results.User == nil {
		p.results.User = &Details{}
	}
	p.results.User.Seed = seed
	return nil
}

func (p *ResolveCmdParams) addSeeds(ctx ActionCtx) error {
	q := p.nscu.query()
	if len(q) == 0 {
		return nil
	}
	v, ok := q["operatorseed"]
	if ok {
		err := p.addOperatorSeed(ctx, v)
		if err != nil {
			return err
		}
	}
	v, ok = q["accountseed"]
	if ok {
		err := p.addAccountSeed(ctx, v)
		if err != nil {
			return err
		}
	}
	v, ok = q["userseed"]
	if ok {
		err := p.addUserSeed(ctx, v)
		if err != nil {
			return err
		}
	}
	_, ok = q["seed"]
	if ok {
		if p.nscu.user != "" {
			err := p.addUserSeed(ctx, "")
			if err != nil {
				return err
			}
		} else if p.nscu.account != "" {
			err := p.addAccountSeed(ctx, "")
			if err != nil {
				return err
			}
		} else {
			err := p.addOperatorSeed(ctx, "")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *ResolveCmdParams) addOperatorName() {
	conf := GetConfig()
	p.results.Operator.Name = conf.Operator
}

func (p *ResolveCmdParams) addAccountName() {
	if p.results.Account == nil {
		p.results.Account = &Details{}
	}
	p.results.Account.Name = p.ac.Name
}

func (p *ResolveCmdParams) addUserName() {
	if p.results.User == nil {
		p.results.User = &Details{}
	}
	p.results.User.Name = p.uc.Name
}

func (p *ResolveCmdParams) addNames() {
	q := p.nscu.query()
	if len(q) == 0 {
		return
	}

	_, ok := q["operatorname"]
	if ok {
		p.addOperatorName()
	}
	_, ok = q["accountname"]
	if ok {
		p.addAccountName()
	}
	_, ok = q["username"]
	if ok {
		p.addUserName()
	}
	_, ok = q["name"]
	if ok {
		if p.nscu.user != "" {
			p.addUserName()
		} else if p.nscu.account != "" {
			p.addAccountName()
		} else {
			p.addOperatorName()
		}
	}
}

func (p *ResolveCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	p.results = &ResolveResults{}
	p.results.Operator = &Details{}
	p.results.Operator.Service = p.oc.OperatorServiceURLs
	if p.nscu.user != "" {
		creds := ctx.StoreCtx().KeyStore.CalcUserCredsPath(p.nscu.account, p.nscu.user)
		if _, err := os.Stat(creds); os.IsNotExist(err) {
			// nothing
		} else {
			p.results.UserCreds = creds
		}
	}
	p.addNames()
	p.addKeys()
	err := p.addSeeds(ctx)
	if err != nil {
		return nil, err
	}
	v, err := json.MarshalIndent(p.results, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := Write(p.outputFile, v); err != nil {
		return nil, err
	}
	var s store.Status
	if !IsStdOut(p.outputFile) {
		s = store.OKStatus("wrote tool configuration to %#q", AbbrevHomePaths(p.outputFile))
	}
	return s, nil
}
