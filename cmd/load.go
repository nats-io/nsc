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
	"os"
	"strings"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/nats-io/nsc/v2/home"

	"github.com/nats-io/jsm.go/natscontext"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

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
			if err := params.setupHomeDir(); err != nil {
				return err
			}
			if err := params.addOperator(); err != nil {
				switch err.Error() {
				case "operator not found":
					cmd.Printf("Unable to find operator %q\n\n", params.operatorName)
					cmd.Printf("If you have used this operator, please enter:")
					cmd.Printf("`nsc env -s /path/to/storedir`\n")
					cmd.Printf("or define the operator endpoint environment:\n")
					cmd.Printf("`NSC_<OPERATOR_NAME>_OPERATOR=http/s://host:port/jwt/v1/operator`\n\n")
				case "bad operator version":
					_ = JWTUpgradeBannerJWT(1)
				default:
				}
				return err
			}
			err := RunAction(cmd, args, &params)
			if err != nil {
				return err
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
	r                *store.Report
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
	userCreds        string
}

func (p *LoadParams) setupHomeDir() error {
	tc := GetConfig()
	sr := tc.StoreRoot
	if sr == "" {
		sr = home.NscDataHome(home.StoresSubDirName)
	}

	sr, err := Expand(sr)
	if err != nil {
		return err
	}
	if err := MaybeMakeDir(sr); err != nil {
		return err
	}
	if err := tc.ContextConfig.setStoreRoot(sr); err != nil {
		return err
	}
	if err := tc.Save(); err != nil {
		return err
	}

	return nil
}

func (p *LoadParams) addOperator() error {
	if p.resourceURL != "" {
		u, err := url.Parse(p.resourceURL)
		if err != nil {
			return err
		}
		p.operatorName = u.Hostname()
		qparams := u.Query()
		p.accountSeed = qparams.Get("secret")
		username := qparams.Get("user")
		if username != "" {
			p.username = username
		}
		ko, err := FindKnownOperator(p.operatorName)
		if err != nil {
			return err
		}
		if ko == nil {
			return fmt.Errorf("operator not found")
		}
		p.accountServerURL = ko.AccountServerURL
	}
	if p.accountServerURL == "" {
		return fmt.Errorf("missing account server URL")
	}

	// Fetch the Operator JWT from the URL to get its claims
	// and setup the local store.
	data, err := LoadFromURL(p.accountServerURL)
	if err != nil {
		return err
	}
	opJWT, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		return err
	}
	operator, err := jwt.DecodeOperatorClaims(opJWT)
	if err != nil {
		return err
	}
	p.operator = operator

	if operator.AccountServerURL == "" {
		return fmt.Errorf("error importing operator %q - it doesn't define an account server url", p.operatorName)
	}

	// Store the Operator locally.
	var (
		onk store.NamedKey
		s   *store.Store
	)
	onk.Name = p.operatorName
	ts, err := GetConfig().LoadStore(onk.Name)
	if err == nil {
		tso, err := ts.ReadOperatorClaim()
		if err == nil {
			if tso.Subject == operator.Subject {
				s = ts
			} else {
				return fmt.Errorf("error a different operator named %q already exists -- specify --dir to create at a different location", onk.Name)
			}
		}
	}
	if s == nil {
		s, err = store.CreateStore(onk.Name, GetConfig().StoreRoot, &onk)
		if err != nil {
			return err
		}
	}
	if err := s.StoreRaw([]byte(opJWT)); err != nil {
		return err
	}
	return nil
}

func (p *LoadParams) addAccount(ctx ActionCtx) error {
	r := p.r
	// Take the seed and generate the public key for the Account then store it.
	// The key is needed to be able to create local user creds as well to configure
	// the context for the NATS CLI.
	operator := p.operator
	seed := p.accountSeed
	if !strings.HasPrefix(seed, "SA") {
		return fmt.Errorf("expected account seed to initialize")
	}
	akp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return fmt.Errorf("failed to parse account name as an nkey: %w", err)
	}
	p.accountKeyPair = akp
	publicAccount, err := akp.PublicKey()
	if err != nil {
		return err
	}
	p.accountPublicKey = publicAccount

	// Fetch Account JWT from URL.
	accountURL := fmt.Sprintf("%s/accounts/%s", operator.AccountServerURL, publicAccount)
	data, err := LoadFromURL(accountURL)
	if err != nil {
		return err
	}
	accJWT, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		return err
	}
	account, err := jwt.DecodeAccountClaims(accJWT)
	if err != nil {
		return err
	}
	p.account = account
	p.accountName = account.Name

	current := GetConfig()
	err = current.ContextConfig.Update(current.StoreRoot, p.operatorName, "")
	if err != nil {
		return err
	}
	// Store the key and JWT.
	_, err = store.StoreKey(akp)
	if err != nil {
		return err
	}
	sctx := ctx.StoreCtx()
	err = sctx.SetContext(p.accountName, p.accountPublicKey)
	if err != nil {
		return err
	}
	ts, err := current.LoadStore(p.operatorName)
	if err != nil {
		return err
	}
	rs, err := ts.StoreClaim([]byte(accJWT))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
	}
	return nil
}

func (p *LoadParams) addUser(ctx ActionCtx) error {
	current := GetConfig()
	err := current.ContextConfig.Update(current.StoreRoot, p.operatorName, p.accountName)
	if err != nil {
		return err
	}

	sctx := ctx.StoreCtx()
	err = sctx.SetContext(p.accountName, p.accountPublicKey)
	if err != nil {
		return err
	}
	ts, err := current.LoadStore(p.operatorName)
	if err != nil {
		return err
	}
	r := p.r

	// NOTE: Stamp the KeyStore env to use the Operator that is being setup.
	sctx.KeyStore.Env = p.operatorName

	// Check if username is already setup, if so then just find the creds instead.
	userFields := []string{store.Accounts, p.accountName, store.Users, store.JwtName(p.username)}
	if ts.Has(userFields...) {
		r.AddWarning("the user %q already exists", p.username)
		creds := sctx.KeyStore.CalcUserCredsPath(p.accountName, p.username)
		if _, err := os.Stat(creds); os.IsNotExist(err) {
			r.AddFromError(fmt.Errorf("user %q credentials not found at %q", p.username, creds))
			return err
		} else {
			p.userCreds = creds
		}
		return nil
	}

	kp, err := nkeys.CreatePair(nkeys.PrefixByteUser)
	if err != nil {
		return err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return err
	}
	uc := jwt.NewUserClaims(pub)
	uc.Name = p.username
	uc.SetScoped(signerKeyIsScoped(ctx, p.accountName, p.accountKeyPair))
	userJWT, err := uc.Encode(p.accountKeyPair)
	if err != nil {
		return err
	}
	st, err := ts.StoreClaim([]byte(userJWT))
	if st != nil {
		r.Add(st)
	}
	if err != nil {
		p.r.AddFromError(err)
		return err
	}
	_, err = sctx.KeyStore.Store(kp)
	if err != nil {
		return err
	}
	r.AddOK("generated and stored user key %q", uc.Subject)

	// Store user credentials.
	userSeed, err := kp.Seed()
	if err != nil {
		return err
	}
	creds, err := jwt.FormatUserConfig(userJWT, userSeed)
	if err != nil {
		return err
	}
	ks := sctx.KeyStore
	path, err := ks.MaybeStoreUserCreds(p.accountName, p.username, creds)
	if err != nil {
		return err
	}
	p.userCreds = path
	r.AddOK("generated and stored user credentials at %q", path)
	return nil
}

func (p *LoadParams) configureNSCEnv() error {
	// Change the current context to the one from load.
	current := GetConfig()

	if err := current.ContextConfig.Update(current.StoreRoot, p.operatorName, p.accountName); err != nil {
		return err
	}
	if err := current.Save(); err != nil {
		return err
	}
	return nil
}

func (p *LoadParams) configureNATSCLI() error {
	p.contextName = fmt.Sprintf("%s_%s_%s", p.operatorName, p.accountName, p.username)

	// Replace this to use instead use the natscontext library.
	var servers string
	if len(p.operator.OperatorServiceURLs) > 0 {
		servers = strings.Join(p.operator.OperatorServiceURLs, ",")
	}
	// Finally, store the NATS context used by the NATS CLI.
	config, err := natscontext.New(p.contextName, false,
		natscontext.WithServerURL(servers),
		natscontext.WithCreds(p.userCreds),
		natscontext.WithDescription(fmt.Sprintf("%s (%s)", p.operatorName, p.operator.Name)),
	)
	if err != nil {
		return err
	}
	config.Save(p.contextName)

	// Switch to use that context as well.
	err = natscontext.SelectContext(p.contextName)
	if err != nil {
		return err
	}
	return nil
}

// Run executes the load profile command.
func (p *LoadParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(false)
	p.r = r
	if err := p.configureNSCEnv(); err != nil {
		return nil, err
	}
	if err := p.addAccount(ctx); err != nil {
		return nil, err
	}
	if err := p.addUser(ctx); err != nil {
		return nil, err
	}
	if err := p.configureNATSCLI(); err != nil {
		return nil, err
	}
	r.AddOK("created nats context %q", p.contextName)
	return r, nil
}

func (p *LoadParams) SetDefaults(ctx ActionCtx) error     { return nil }
func (p *LoadParams) PreInteractive(ctx ActionCtx) error  { return nil }
func (p *LoadParams) Load(ctx ActionCtx) error            { return nil }
func (p *LoadParams) PostInteractive(ctx ActionCtx) error { return nil }
func (p *LoadParams) Validate(ctx ActionCtx) error        { return nil }
