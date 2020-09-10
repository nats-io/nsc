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

func createProfileCmd() *cobra.Command {
	var params ProfileCmdParams
	var cmd = &cobra.Command{
		Use:   "profile",
		Short: "Generate a profile from nsc 'URL' that can be used by tooling",
		Example: `profile nsc://operator
resolve nsc://operator/account
resolve nsc://operator/account/user
resolve nsc://operator/account/user?operatorSeed&accountSeed&userSeed
resolve nsc://operator/account/user?operatorKey&accountKey&userKey
resolve nsc://operator?key&seed
resolve nsc://operator/account?key&seed
resolve nsc://operator/account/user?key&seed
resolve nsc://operator/account/user?store=/a/.nsc/nats&keystore=/foo/.nkeys

Output of the program looks like:
{
  "user_creds": "<filepath>",
  "operator" : {
     "service": "hostport"
   }
}
The user_creds is printed if an user is specified
Other options (as query string arguments):
keystore=<dir> that specifies the location of the keystore

store=<dir> that specifies a directory that contains the named operator

[user|account|operator]Key - includes the public key for user, account, 
operator, If no prefix (user/account/operator is provided, it targets 
the last object in the configuration path)

[user|account|operator]Seed=<optional public key> - include the seed for 
user, account, operator, if an argument is provided, the seed for the 
specified public key is provided - this allows targeting a signing key.
If no prefix (user/account/operator is provided, it targets the last 
object in the configuration path)

[user|account|operator]Name - includes the friendly name for the for 
user, account, operator, If no prefix (user/account/operator is provided, 
it targets the last object in the configuration path)
		`,

		Args: MaxArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			us := args[0]
			u, err := ParseNscURL(us)
			if err != nil {
				return fmt.Errorf("error parsing %q:%v", us, err)
			}
			params.nscu = u
			q, err := u.query()
			if err != nil {
				return fmt.Errorf("error parsing query %q:%v", us, err)
			}
			if len(q) > 0 {
				config := GetConfig()
				oldSR := config.StoreRoot
				oldOp := config.Operator
				oldAc := config.Account
				v, ok := q["store"]
				if ok {
					defer func() {
						_ = config.setStoreRoot(oldSR)
						if oldOp != "" {
							_ = config.SetOperator(oldOp)
						}
						if oldAc != "" {
							_ = config.SetAccount(oldAc)
						}
					}()
					sr, err := Expand(v)
					if err != nil {
						return err
					}
					if err := config.setStoreRoot(sr); err != nil {
						return err
					}
					if err := config.SetOperator(u.operator); err != nil {
						return err
					}
				}

				storeDir, ok := q[keystoreDir]
				if ok {
					ks, err := Expand(storeDir)
					if err != nil {
						return err
					}
					if err := os.Setenv(store.NKeysPathEnv, ks); err != nil {
						return err
					}
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
	generateCmd.AddCommand(createProfileCmd())
}

type Arg string

const (
	prefix           = "nsc://"
	operatorKey  Arg = "operatorkey"
	accountKey   Arg = "accountkey"
	userKey      Arg = "userkey"
	key          Arg = "key"
	operatorSeed Arg = "operatorseed"
	accountSeed  Arg = "accountseed"
	userSeed     Arg = "userseed"
	seed         Arg = "seed"
	operatorName Arg = "operatorname"
	accountName  Arg = "accountname"
	userName     Arg = "username"
	name         Arg = "name"
	keystoreDir  Arg = "keystore"
	storeDir     Arg = "store"
)

type ProfileCmdParams struct {
	nscu       *NscURL
	results    *Profile
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

type Profile struct {
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

type stringSet struct {
	set map[string]string
}

func newStringSet() *stringSet {
	var s stringSet
	s.set = make(map[string]string)
	return &s
}

func (u *stringSet) add(s string) {
	u.set[strings.ToLower(s)] = s
}

func (u *stringSet) contains(s string) bool {
	return u.set[strings.ToLower(s)] != ""
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

func (u *NscURL) query() (map[Arg]string, error) {
	q := strings.ToLower(u.qs)
	m := make(map[Arg]string)
	for _, e := range strings.Split(q, "&") {
		kv := strings.Split(e, "=")
		k := strings.ToLower(kv[0])
		v := ""
		if len(kv) == 2 {
			s, err := url.QueryUnescape(kv[1])
			if err != nil {
				return nil, err
			}
			v = s
		}
		m[Arg(k)] = v
	}
	return m, nil
}

func ParseNscURL(u string) (*NscURL, error) {
	var v NscURL
	s := u
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

func (p *ProfileCmdParams) SetDefaults(_ ActionCtx) error {
	return nil
}

func (p *ProfileCmdParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *ProfileCmdParams) Load(_ ActionCtx) error {
	return nil
}

func (p *ProfileCmdParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *ProfileCmdParams) loadNames(c jwt.Claims) *stringSet {
	names := newStringSet()
	cd := c.Claims()
	names.add(cd.Name)
	names.add(cd.Subject)

	conf := GetConfig()
	payload := c.Payload()
	_, ok := payload.(jwt.Operator)
	if ok && conf.Operator != "" {
		names.add(conf.Operator)
	}
	return names
}

func (p *ProfileCmdParams) checkLoadOperator(ctx ActionCtx) error {
	conf := GetConfig()
	if conf.Operator == "" {
		return errors.New("no operator set - `env --operator <name>`")
	}

	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	names := p.loadNames(oc)
	names.add(conf.Operator)

	if !names.contains(p.nscu.operator) {
		return fmt.Errorf("invalid operator %q: make sure you have the right operator context", p.nscu.operator)
	}
	p.nscu.operator = oc.Name
	p.oc = oc
	return nil
}

func (p *ProfileCmdParams) checkLoadAccount(ctx ActionCtx) error {
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
			continue
		}
		aliases := p.loadNames(ac)
		if aliases.contains(p.nscu.account) {
			p.nscu.account = ac.Name
			p.ac = ac
			return nil
		}
	}
	return fmt.Errorf("invalid account %q: account was not found", p.nscu.account)
}

func (p *ProfileCmdParams) checkLoadUser(ctx ActionCtx) error {
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
			continue
		}
		aliases := p.loadNames(uc)
		if aliases.contains(p.nscu.user) {
			p.nscu.user = uc.Name
			p.uc = uc
			return nil
		}
	}
	return fmt.Errorf("invalid user %q: user was not found", p.nscu.user)
}

func (p *ProfileCmdParams) Validate(ctx ActionCtx) error {
	if err := p.checkLoadOperator(ctx); err != nil {
		return err
	}
	if err := p.checkLoadAccount(ctx); err != nil {
		return err
	}
	return p.checkLoadUser(ctx)
}

func (p *ProfileCmdParams) addOperatorKeys() {
	p.results.Operator.Key = p.oc.Subject
}

func (p *ProfileCmdParams) addAccountKeys() {
	if p.results.Account == nil {
		p.results.Account = &Details{}
	}
	p.results.Account.Key = p.ac.Subject
}

func (p *ProfileCmdParams) addUserKeys() {
	if p.results.User == nil {
		p.results.User = &Details{}
	}
	p.results.User.Key = p.uc.Subject
}

func (p *ProfileCmdParams) addKeys() error {
	q, err := p.nscu.query()
	if err != nil {
		return err
	}
	if len(q) == 0 {
		return nil
	}
	_, ok := q[operatorKey]
	if ok {
		p.addOperatorKeys()
	}
	_, ok = q[accountKey]
	if ok {
		p.addAccountKeys()
	}
	_, ok = q[userKey]
	if ok {
		p.addUserKeys()
	}
	_, ok = q[key]
	if ok {
		if p.nscu.user != "" {
			p.addUserKeys()
		} else if p.nscu.account != "" {
			p.addAccountKeys()
		} else {
			p.addOperatorKeys()
		}
	}
	return nil
}

func (p *ProfileCmdParams) getKeys(claim jwt.Claims) []string {
	var keys []string
	if claim != nil {
		keys = append(keys, claim.Claims().Subject)
		var payload = claim.Payload()
		oc, ok := payload.(*jwt.Operator)
		if ok {
			keys = append(keys, oc.SigningKeys...)
		}
		ac, ok := payload.(*jwt.Account)
		if ok {
			keys = append(keys, ac.SigningKeys...)
		}
	}
	return keys
}

func (p *ProfileCmdParams) resolveSeed(ctx ActionCtx, s string, keys []string) (string, error) {
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

func (p *ProfileCmdParams) addOperatorSeed(ctx ActionCtx, v string) error {
	seed, err := p.resolveSeed(ctx, v, p.getKeys(p.oc))
	if err != nil {
		return err
	}
	p.results.Operator.Seed = seed
	return nil
}

func (p *ProfileCmdParams) addAccountSeed(ctx ActionCtx, v string) error {
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

func (p *ProfileCmdParams) addUserSeed(ctx ActionCtx, v string) error {
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

func (p *ProfileCmdParams) addSeeds(ctx ActionCtx) error {
	q, err := p.nscu.query()
	if err != nil {
		return err
	}
	if len(q) == 0 {
		return nil
	}
	v, ok := q[operatorSeed]
	if ok {
		err := p.addOperatorSeed(ctx, v)
		if err != nil {
			return err
		}
	}
	v, ok = q[accountSeed]
	if ok {
		err := p.addAccountSeed(ctx, v)
		if err != nil {
			return err
		}
	}
	v, ok = q[userSeed]
	if ok {
		err := p.addUserSeed(ctx, v)
		if err != nil {
			return err
		}
	}
	_, ok = q[seed]
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

func (p *ProfileCmdParams) addOperatorName() {
	conf := GetConfig()
	p.results.Operator.Name = conf.Operator
}

func (p *ProfileCmdParams) addAccountName() {
	if p.results.Account == nil {
		p.results.Account = &Details{}
	}
	p.results.Account.Name = p.ac.Name
}

func (p *ProfileCmdParams) addUserName() {
	if p.results.User == nil {
		p.results.User = &Details{}
	}
	p.results.User.Name = p.uc.Name
}

func (p *ProfileCmdParams) addNames() error {
	q, err := p.nscu.query()
	if err != nil {
		return err
	}
	if len(q) == 0 {
		return nil
	}

	_, ok := q[operatorName]
	if ok {
		p.addOperatorName()
	}
	_, ok = q[accountName]
	if ok {
		p.addAccountName()
	}
	_, ok = q[userName]
	if ok {
		p.addUserName()
	}
	_, ok = q[name]
	if ok {
		if p.nscu.user != "" {
			p.addUserName()
		} else if p.nscu.account != "" {
			p.addAccountName()
		} else {
			p.addOperatorName()
		}
	}
	return nil
}

func (p *ProfileCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	p.results = &Profile{}
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
	if err := p.addNames(); err != nil {
		return nil, err
	}
	if err := p.addKeys(); err != nil {
		return nil, err
	}
	if err := p.addSeeds(ctx); err != nil {
		return nil, err
	}
	v, err := json.MarshalIndent(p.results, "", "  ")
	v = append(v, '\n')
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
