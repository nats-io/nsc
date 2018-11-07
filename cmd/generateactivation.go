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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createGenerateActivationCmd() *cobra.Command {
	var params GenerateActivationParams
	cmd := &cobra.Command{
		Use:   "activation",
		Short: "generate an activation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}

			jti, err := params.Run()
			if err != nil {
				return err
			}

			if !IsStdOut(params.outputFile) {
				cmd.Printf("Generated activation to %q - this activation can be revoked with JTI %q\n", params.outputFile, jti)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.public, "public", "", false, "generates an activation token containing all the public exports in the account")
	cmd.Flags().StringSliceVarP(&params.serviceSubject, "service", "", nil, "add activation service subject")
	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "source network for connection - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.streamSubject, "stream", "", nil, "add activation stream subject")
	cmd.Flags().StringVarP(&params.expiry, "expiry", "e", "30d", "expiry for jwt (default 30 days - specify '0' for no expiration) - supported patterns include: yyyy-mm-dd, n(m)inutes, n(h)ours, n(d)ays, n(w)eeks, n(M)onths, n(y)ears")
	cmd.Flags().StringVarP(&params.max, "max-messages", "", "", "max messages - number optionally followed by units (K)ilo, (M)illion, (G)iga")
	cmd.Flags().StringVarP(&params.name, "name", "", "", "name for the activation token")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.payload, "max-payload", "", "", "max message payload - number followed by units (b)yte, (k)b, (M)egabyte")
	cmd.Flags().StringVarP(&params.publicKey, "public-key", "k", "", "public key of the subject accessing the service")

	cmd.MarkFlagRequired("name")

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateActivationCmd())
}

type GenerateActivationParams struct {
	max            string
	name           string
	outputFile     string
	payload        string
	publicKey      string
	serviceSubject []string
	src            []string
	streamSubject  []string
	public         bool
	expiry         string
}

func (p *GenerateActivationParams) Validate() error {
	if p.publicKey == "" && !p.public {
		return errors.New("error specify --public or --public-key")
	}

	if p.publicKey != "" && !nkeys.IsValidPublicAccountKey([]byte(p.publicKey)) {
		return fmt.Errorf("error public key %q is not a valid account public key", p.publicKey)
	}

	if !p.public && p.serviceSubject == nil && p.streamSubject == nil {
		return fmt.Errorf("error specify one of --public, --service, or --stream")
	}

	if p.expiry != "" {
		if _, err := ParseExpiry(p.expiry); err != nil {
			return err
		}
	}

	if p.max != "" {
		if _, err := ParseNumber(p.max); err != nil {
			return err
		}
	}

	if p.payload != "" {
		if _, err := ParseDataSize(p.payload); err != nil {
			return err
		}
	}

	if p.expiry != "" {
		expiry, err := ParseExpiry(p.expiry)
		if err != nil {
			return err
		}
		if expiry > 0 && time.Now().Unix() > expiry {
			return errors.New("expiry date is already past")
		}
	}

	return nil
}

func (p *GenerateActivationParams) Run() (string, error) {
	sub := p.publicKey
	if sub == "" && p.public {
		sub = "public"
	}

	ac := jwt.NewActivationClaims(sub)
	ac.Name = p.name
	ac.Expires, _ = ParseExpiry(p.expiry)

	s, err := getStore()
	if err != nil {
		return "", fmt.Errorf("error loading store: %v", err)
	}

	if p.public {
		exports, err := ListExports()
		if err != nil {
			return "", err
		}
		for _, e := range exports {
			ac.Exports.Add(e.Export)
		}
	} else {
		for _, v := range p.serviceSubject {
			s := jwt.Export{}
			s.Subject = jwt.Subject(v)
			s.Type = jwt.ServiceType
			ac.Exports.Add(s)
		}
		for _, v := range p.streamSubject {
			s := jwt.Export{}
			s.Subject = jwt.Subject(v)
			s.Type = jwt.StreamType
			ac.Exports.Add(s)
		}
	}

	if p.max != "" {
		ac.Limits.Max, _ = ParseNumber(p.max)
	}

	if p.payload != "" {
		ac.Limits.Payload, _ = ParseDataSize(p.payload)
	}

	if len(p.src) > 0 {
		ac.Limits.Src = strings.Join(p.src, ",")
	}

	kp, err := s.GetKey()
	if err != nil {
		return "", err
	}

	token, err := ac.Encode(kp)
	if err != nil {
		return "", err
	}

	d := FormatJwt("activation", token)

	if err := s.WriteToken(token); err != nil {
		return "", err
	}

	if err := Write(p.outputFile, d); err != nil {
		return "", err
	}

	return ac.ID, nil
}
