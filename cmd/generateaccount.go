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
	"fmt"
	"path/filepath"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func createGenerateAccountCmd() *cobra.Command {
	var params GenerateAccountParams
	var cmd = &cobra.Command{
		Use:   "account",
		Short: "Generate an account JWT",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote account jwt to %q\n", params.outputFile)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.expiry, "expiry", "e", "30d", "expiry for jwt (default 30 days - specify '0' for no expiration) - supported patterns include: yyyy-mm-dd, n(m)inutes, n(h)ours, n(d)ays, n(w)eeks, n(M)onths, n(y)ears")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	return cmd
}

type GenerateAccountParams struct {
	expiry     string
	outputFile string
}

func (p *GenerateAccountParams) Validate() error {
	if p.expiry != "" {
		expiry, err := ParseExpiry(p.expiry)
		if err != nil {
			return err
		}
		if expiry > 0 && time.Now().Unix() > expiry {
			return errors.New("expiry date is already past")
		}
	}

	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v\n", err)
	}

	if s.Has(store.AccountActivation) {
		a, err := s.GetAccountActivation()
		if err != nil {
			return fmt.Errorf("error loading account activation: %v", err)
		}

		ac, err := jwt.DecodeActivationClaims(a)
		if err != nil {
			return fmt.Errorf("error parsing account activation: %v", err)
		}

		now := time.Now().Unix()
		if now > ac.Expires {
			return fmt.Errorf("account activation is expired")
		}
	}

	return nil
}

func GenerateAccountJWT(expiry string) (string, error) {
	s, err := getStore()
	if err != nil {
		return "", fmt.Errorf("error generating account jwt: %v", err)
	}

	var accountActivation string
	if s.Has(store.AccountActivation) {
		accountActivation, err = s.GetAccountActivation()
		if err != nil {
			return "", fmt.Errorf("error loading account activation: %v", err)
		}
		_, err = jwt.DecodeActivationClaims(accountActivation)
		if err != nil {
			return "", fmt.Errorf("error parsing account activation: %v", err)
		}
	}

	pk, err := s.GetPublicKey()
	if err != nil {
		return "", fmt.Errorf("error reading public key: %v", err)
	}

	acct := jwt.NewAccountClaims(pk)
	acct.Access = accountActivation
	acct.Expires, _ = ParseExpiry(expiry)

	var imports Imports
	if s.Has(store.Imports) {
		if err := s.ReadEntry(store.Imports, &imports); err != nil {
			return "", fmt.Errorf("error loading imports: %v", err)
		}
	}

	now := time.Now().Unix()
	for _, v := range imports {
		act, err := s.Read(filepath.Join(store.Activations, v.JTI+".jwt"))
		if err != nil {
			return "", fmt.Errorf("error reading %q: %v", v.JTI+".jwt", err)
		}
		claim, err := jwt.DecodeActivationClaims(string(act))
		if err != nil {
			return "", fmt.Errorf("error parsing activation: %v", err)
		}

		if now > claim.Expires {
			return "", fmt.Errorf("error account references an expired activation %q", v.JTI)
		}

		var found *jwt.Export
		for _, es := range claim.Exports {
			if es.Subject == v.Subject {
				found = &es
				break
			}
		}

		if found == nil {
			return "", fmt.Errorf("an export with subject %q was not found in jwt", v.Subject)
		}

		is := jwt.Import{}
		is.Auth = string(act)
		is.Subject = v.Subject
		is.Name = v.Name

		if found.IsStream() {
			is.Type = jwt.StreamType
			is.Prefix = v.Map
		}

		if found.IsService() {
			is.Type = jwt.ServiceType
			is.To = v.Map
		}

		acct.Imports.Add(is)
	}

	exports, err := ListExports()
	if err != nil {
		return "", fmt.Errorf("error loading exports: %v\n", err)
	}

	for _, v := range exports {
		acct.Exports.Add(v.Export)
	}

	kp, err := s.GetKey()
	if err != nil {
		return "", fmt.Errorf("error reading account key: %v\n", err)
	}

	jwt, err := acct.Encode(kp)
	if err != nil {
		return "", fmt.Errorf("error encoding account jwt: %v\n", err)
	}

	return jwt, nil
}

func (p *GenerateAccountParams) Run() error {
	token, err := GenerateAccountJWT(p.expiry)
	if err != nil {
		return err
	}
	// store a copy for revocation
	s, err := getStore()
	if err != nil {
		return err
	}

	if err := s.WriteToken(token); err != nil {
		return err
	}

	return Write(p.outputFile, FormatJwt("account", token))
}

func init() {
	generateCmd.AddCommand(createGenerateAccountCmd())
}
