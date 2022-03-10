// Copyright 2022 The NATS Authors
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
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/nats-io/nsc/home"
	"github.com/spf13/cobra"
)

func createLoadCmd() *cobra.Command {
	var params LoadParams
	cmd := &cobra.Command{
		Use:   "load",
		Short: "install entities for an operator, account and key",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Note: Need to initialize the operator and environment
			// before the RunAction command since that is dependent
			// on an operator being available.
			params.setupHomeDir()
			params.addOperator()
			err := RunAction(cmd, args, &params)
			if err != nil {
				switch err.Error() {
				case "operator not found":
					cmd.Printf("Unable to find operator %q\n", params.operatorName)
					cmd.Printf("If you have used this operator, please enter:")
					cmd.Printf("`nsc env -s /path/to/storedir`")
				case "bad operator version":
					_ = JWTUpgradeBannerJWT(1)
				default:
				}
			}
			return err
		},
	}

	cmd.Flags().StringVarP(&params.resourceURL, "profile", "", "", "Profile URL to initialize NSC and NATS CLI env")
	cmd.Flags().StringVarP(&params.accountServerURL, "url", "", "", "URL of the account server")
	cmd.Flags().StringVarP(&params.accountSeed, "seed", "", "", "Seed of the account used to create users")
	cmd.Flags().StringVarP(&params.username, "user", "", "default", "Default username")
	return cmd
}

func init() {
	rootCmd.AddCommand(createLoadCmd())
}

// LoadParams prepares an NSC environment and NATS Cli context based
// on the URL of and Account seed.  Requires NATS CLI to be in PATH
// to complete the setup of a user profile.
type LoadParams struct {
	err              error
	r                *store.Report
	ctx              *store.Context
	resourceURL      string
	operatorName     string
	operator         *jwt.OperatorClaims
	accountName      string
	accountSeed      string
	accountPublicKey string
	account          *jwt.AccountClaims
	accountKeyPair   nkeys.KeyPair
	accountServerURL string
	username         string
	contextName      string
}

func (p *LoadParams) setupHomeDir() {
	tc := GetConfig()
	sr := tc.StoreRoot
	if sr == "" {
		sr = home.NscDataHome(home.StoresSubDirName)
	}

	sr, err := Expand(sr)
	if err != nil {
		p.err = err
		return
	}
	if err := MaybeMakeDir(sr); err != nil {
		p.err = err
		return
	}
	if err := tc.ContextConfig.setStoreRoot(sr); err != nil {
		p.err = err
		return
	}
	if err := tc.Save(); err != nil {
		p.err = err
		return
	}
}

func (p *LoadParams) addOperator() {
	if p.err != nil {
		return
	}
	fmt.Println(p.resourceURL)
	if p.resourceURL != "" {
		u, err := url.Parse(p.resourceURL)
		if err != nil {
			p.err = err
			return
		}
		p.operatorName = u.Hostname()
		qparams := u.Query()
		p.accountSeed = qparams.Get("secret")
		p.username = qparams.Get("user")
		if p.username == "" {
			p.username = "default"
		}
		ko, err := FindKnownOperator(p.operatorName)
		if err != nil {
			p.err = err
			return
		}
		p.accountServerURL = ko.AccountServerURL
	}
	if p.accountServerURL == "" {
		p.err = fmt.Errorf("missing account server URL")
		return
	}

	// Fetch the Operator JWT from the URL to get its claims
	// and setup the local store.
	data, err := LoadFromURL(p.accountServerURL)
	if err != nil {
		p.err = err
		return
	}
	opJWT, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		p.err = err
		return
	}
	operator, err := jwt.DecodeOperatorClaims(opJWT)
	if err != nil {
		p.err = err
		return
	}
	p.operator = operator
	p.contextName = fmt.Sprintf("nsc-%s-%s-user", p.operator.Name, p.username)

	if operator.AccountServerURL == "" {
		p.err = fmt.Errorf("error importing operator %q - it doesn't define an account server url", operator.Name)
		return
	}

	// Store the Operator locally.
	var (
		onk store.NamedKey
		s   *store.Store
	)
	onk.Name = operator.Name
	ts, err := GetConfig().LoadStore(onk.Name)
	if err == nil {
		tso, err := ts.ReadOperatorClaim()
		if err == nil {
			if tso.Subject == operator.Subject {
				s = ts
			} else {
				p.err = fmt.Errorf("error a different operator named %q already exists -- specify --dir to create at a different location", onk.Name)
				return
			}
		}
	}
	if s == nil {
		s, err = store.CreateStore(onk.Name, GetConfig().StoreRoot, &onk)
		if err != nil {
			p.err = err
			return
		}
	}
	if err := s.StoreRaw([]byte(opJWT)); err != nil {
		p.err = err
	}
}

func (p *LoadParams) addAccount(ctx ActionCtx) {
	if p.err != nil {
		return
	}
	r := p.r
	// Take the seed and generate the public key for the Account then store it.
	// The key is needed to be able to create local user creds as well to configure
	// the context for the NATS CLI.
	operator := p.operator
	seed := p.accountSeed
	if !strings.HasPrefix(seed, "SA") {
		p.err = fmt.Errorf("expected account seed to initialize")
		return
	}
	akp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		p.err = fmt.Errorf("failed to parse account name as an nkey: %w", err)
		return
	}
	p.accountKeyPair = akp
	publicAccount, err := akp.PublicKey()
	if err != nil {
		p.err = err
		return
	}
	p.accountPublicKey = publicAccount

	// Fetch Account JWT from URL.
	accountURL := fmt.Sprintf("%s/accounts/%s", operator.AccountServerURL, publicAccount)
	data, err := LoadFromURL(accountURL)
	if err != nil {
		p.err = err
		return
	}
	accJWT, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		p.err = err
		return
	}
	account, err := jwt.DecodeAccountClaims(accJWT)
	if err != nil {
		p.err = err
		return
	}
	p.account = account
	p.accountName = account.Name

	// Store the key and JWT.
	_, err = store.StoreKey(akp)
	if err != nil {
		p.err = err
		return
	}
	StoreAccountAndUpdateStatus(ctx, accJWT, r)
}

func (p *LoadParams) addUser(ctx ActionCtx) {
	if p.err != nil {
		return
	}
	s := p.ctx.Store
	r := p.r

	// Check if username is already setup.
	if s.Has(store.Accounts, p.ctx.Account.Name, store.Users, store.JwtName(p.username)) {
		r.AddWarning("the user %q already exists", p.username)
		return
	}
	kp, err := nkeys.CreatePair(nkeys.PrefixByteUser)
	if err != nil {
		p.err = err
		return
	}
	pub, err := kp.PublicKey()
	if err != nil {
		p.err = err
		return
	}
	uc := jwt.NewUserClaims(pub)
	uc.Name = p.username
	uc.SetScoped(signerKeyIsScoped(ctx, p.accountName, p.accountKeyPair))
	userJWT, err := uc.Encode(p.accountKeyPair)
	if err != nil {
		p.err = err
		return
	}
	st, err := ctx.StoreCtx().Store.StoreClaim([]byte(userJWT))
	if st != nil {
		r.Add(st)
	}
	if err != nil {
		p.r.AddFromError(err)
		p.err = err
		return
	}
	_, err = ctx.StoreCtx().KeyStore.Store(kp)
	if err != nil {
		p.err = err
		return
	}
	r.AddOK("generated and stored user key %q", uc.Subject)

	// Store user credentials.
	userSeed, err := kp.Seed()
	if err != nil {
		p.err = err
	}
	creds, err := jwt.FormatUserConfig(userJWT, userSeed)
	if err != nil {
		p.err = err
		return
	}
	ks := ctx.StoreCtx().KeyStore
	path, err := ks.MaybeStoreUserCreds(p.accountName, p.username, creds)
	if err != nil {
		p.err = err
		return
	}
	r.AddOK("generated and stored user credentials at %q", path)
}

func (p *LoadParams) configureCLI(ctx ActionCtx) {
	if p.err != nil {
		return
	}
	path, err := exec.LookPath("nats")
	if err != nil {
		p.err = fmt.Errorf("cannot find 'natscli' in user path")
		return
	}

	cmd := exec.Command(
		path,
		"context",
		"save",
		p.contextName,
		"--nsc",
		fmt.Sprintf("nsc://%s/%s/%s", p.operator.Name, p.account.Name, p.username),
	)
	_, err = cmd.CombinedOutput()
	if err != nil {
		p.err = fmt.Errorf("nsc invoke failed: %s", err)
		return
	}
}

// Run executes the load profile command.
func (p *LoadParams) Run(ctx ActionCtx) (store.Status, error) {
	if p.err != nil {
		return nil, p.err
	}
	r := store.NewDetailedReport(false)
	p.r = r
	p.ctx = ctx.StoreCtx()
	p.addAccount(ctx)
	p.addUser(ctx)
	p.configureCLI(ctx)
	if p.err != nil {
		return nil, p.err
	}
	r.AddOK("created nats context %q", p.contextName)
	return r, nil
}

func (p *LoadParams) SetDefaults(ctx ActionCtx) error     { return nil }
func (p *LoadParams) PreInteractive(ctx ActionCtx) error  { return nil }
func (p *LoadParams) Load(ctx ActionCtx) error            { return nil }
func (p *LoadParams) PostInteractive(ctx ActionCtx) error { return nil }
func (p *LoadParams) Validate(ctx ActionCtx) error        { return nil }
