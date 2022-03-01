/*
 * Copyright 2018-2022 The NATS Authors
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
	"reflect"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createLoadCmd() *cobra.Command {
	var params LoadParams
	cmd := &cobra.Command{
		Use:   "load",
		Short: "install entities for an operator, account and key",
		RunE: func(cmd *cobra.Command, args []string) error {
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

	cmd.Flags().StringVarP(&params.Profile, "profile", "p", "", "profile url")
	return cmd
}

func init() {
	rootCmd.AddCommand(createLoadCmd())
}

type LoadParams struct {
	Profile       string
	nscURL        *NscURL
	operatorName  string
	operatorToken string
	operatorClaim *jwt.OperatorClaims
	accountToken  string
	accountClaim  *jwt.AccountClaims
}

func (p *LoadParams) SetDefaults(ctx ActionCtx) error {
	var err error
	p.nscURL, err = ParseNscURL(p.Profile)
	return err

}

func (p *LoadParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *LoadParams) loadOperator(r *store.Report) error {
	var err error
	p.operatorName, err = p.nscURL.getOperator()
	if err != nil {
		return err
	}
	s, err := GetConfig().LoadStore(p.operatorName)
	if err != nil {
		// either doesn't exist or there was an error
		ko, err := FindKnownOperator(p.operatorName)
		if err != nil {
			r.AddError("there was an error finding %q operator: %w", p.operatorName, err)
			return err
		}
		if ko == nil {
			r.AddError("%q is not a well known operator, import it first", p.operatorName)
			return errors.New("operator not found")
		}
		data, err := LoadFromURL(ko.AccountServerURL)
		if err != nil {
			r.AddError("failed to load operator from %s: %w", ko.AccountServerURL, err)
			return err
		}
		p.operatorToken, err = jwt.ParseDecoratedJWT(data)
		if err != nil {
			r.AddError("failed to parse JWT from %s: %w", ko.AccountServerURL, err)
			return err
		}
		p.operatorClaim, err = jwt.DecodeOperatorClaims(p.operatorToken)
		if err != nil {
			r.AddError("failed to decode JWT from %s: %w", ko.AccountServerURL, err)
			return err
		}

	} else {
		r.AddOK("found operator %q locally", p.operatorName)
		p.operatorClaim, err = s.ReadOperatorClaim()
		if err != nil {
			r.AddError("failed to read operator %w", err)
			return fmt.Errorf("error reading operator %w", err)
		}
	}
	if p.operatorClaim.Version < 2 {
		r.AddError("unsupported operator JWT version (%d)", p.operatorClaim.Version)
		return fmt.Errorf("bad operator version")
	}
	return nil
}

func (p *LoadParams) loadAccount(r *store.Report) error {
	an, err := p.nscURL.getAccount()
	if err != nil {
		return err
	}

	if an == "" {
		r.AddWarning("account was not specified")
		return nil
	}

	var kp nkeys.KeyPair
	// if we have an account name does it look like an nkey?
	if strings.HasPrefix(an, "A") {
		kp, err = nkeys.FromPublicKey(an)
		if err != nil {
			r.AddError("failed to parse account name as an nkey: %w", err)
			return err
		}
	} else if strings.HasPrefix(an, "SA") {
		kp, err = nkeys.FromSeed([]byte(an))
		if err != nil {
			r.AddError("failed to parse account name as an nkey: %w", err)
			return err
		}
	}

	var aidURL = ""
	if kp != nil && !reflect.ValueOf(kp).IsNil() {
		aid, err := kp.PublicKey()
		if err != nil {
			r.AddError("failed to get public key: %w", err)
			return err
		}
		// https://host:port/jwt/v2/operator
		// https://host:port/jwt/v1/accounts/<accountid>
		aidURL = fmt.Sprintf("%s/accounts/%s", p.operatorClaim.AccountServerURL, aid)
	}
	if aidURL != "" {
		data, err := LoadFromURL(aidURL)
		if err != nil {
			r.AddError("failed to load account from %s: %w", aidURL, err)
			return err
		}
		p.accountToken, err = jwt.ParseDecoratedJWT(data)
		if err != nil {
			r.AddError("failed to parse JWT from %s: %w", aidURL, err)
			return err
		}
		p.accountClaim, err = jwt.DecodeAccountClaims(p.accountToken)
		if err != nil {
			r.AddError("failed to decode JWT from %s: %w", aidURL, err)
			return err
		}

		// check if the account exist
		s, err := GetConfig().LoadStore(p.operatorName)
		if err == nil {
			ac, _ := s.ReadAccountClaim(p.accountClaim.Name)
			if ac != nil && !reflect.ValueOf(ac).IsNil() {
				if ac.Subject == p.accountClaim.Subject {
					r.AddError("account %q already installed as %s", ac.Subject, ac.Name)
				}
				if ac.Subject != p.accountClaim.Subject {
					r.AddError("an different account %q is already installed as %s\nrename the existing account first:\nnsc rename %s <newname>", ac.Subject, ac.Name, ac.Name)
				}
			}
		}
	}
	return nil
}

func (p *LoadParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *LoadParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *LoadParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *LoadParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(false)
	if err := p.loadOperator(r); err != nil {
		return r, err
	}
	if err := p.loadAccount(r); err != nil {
		return r, err
	}
	// add the operator
	// add the account
	// store the key
	// add a user
	// create a nats cli profile that references this profile
	// print a message that shows:
	// to test your configuration try:
	// nsc publish -a <account name> hello world
	// or
	// nats profile select "account name"
	// nats pub hello world
	return r, nil
}
