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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

// addCmd represents the add command
func createInitAccountCmd() *cobra.Command {
	var params InitAccountParams

	var cmd = &cobra.Command{
		Use:    "account",
		Hidden: !show,
		Short:  "initializes the current directory for account configurations",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(cmd); err != nil {
				return err
			}
			if err := params.Run(args); err != nil {
				return err
			}

			d, err := params.kp.Seed()
			if err != nil {
				return fmt.Errorf("error reading seed: %v", err)
			}

			if params.generate {
				d := FormatKeys("account", params.publicKey, string(d))
				if err := Write("--", d); err != nil {
					return err
				}
			} else {
				cmd.Printf("Success! - account created %q\n", params.publicKey)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.generate, "generate-nkeys", "", false, "generate account nkey")
	cmd.Flags().StringVarP(&params.name, "name", "", "", "name for the account")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("private-key")

	return cmd
}

func init() {
	initCmd.AddCommand(createInitAccountCmd())
}

type InitAccountParams struct {
	generate  bool
	name      string
	kp        nkeys.KeyPair
	publicKey string
}

func (p *InitAccountParams) Validate(cmd *cobra.Command) error {
	var err error

	p.name = strings.TrimSpace(p.name)
	if strings.HasSuffix(p.name, " ") {
		return fmt.Errorf("names cannot have spaces: %q", p.name)
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting cwd: %v", err)
	}

	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	if len(infos) != 0 {
		return fmt.Errorf("directory %q is not empty", dir)
	}

	if p.generate && cmd.Flag("private-key").Changed {
		return errors.New("provide only one of --generate-nkeys or --private-key")
	}

	if p.generate {
		p.kp, err = nkeys.CreateAccount()
		if err != nil {
			return fmt.Errorf("error creating account key: %v", err)
		}
	}

	if cmd.Flag("private-key").Changed {
		p.kp, err = GetSeed()
		if err != nil {
			return fmt.Errorf("error parsing seed: %v", err)
		}
		pk, err := p.kp.PublicKey()
		if err != nil {
			return fmt.Errorf("error reading public key: %v", err)
		}

		if !nkeys.IsValidPublicAccountKey(pk) {
			return fmt.Errorf("%q is not a valid account key", string(pk))
		}
	}

	return nil
}

func (p *InitAccountParams) Run(args []string) error {
	if err := p.CreateStore(); err != nil {
		return err
	}
	if err := p.CreateDirs(); err != nil {
		return err
	}
	if err := p.WriteJwt(); err != nil {
		return err
	}

	return nil
}

func (p *InitAccountParams) CreateStore() error {
	var err error
	d, err := p.kp.PublicKey()
	if err != nil {
		return fmt.Errorf("error reading or creating account public key: %v", err)
	}
	p.publicKey = string(d)

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting cwd: %v", err)
	}
	_, err = store.CreateStore(dir, p.publicKey, "account", p.name)
	return err
}

func (p *InitAccountParams) CreateDirs() error {
	// make some directories
	s, err := getStore()
	if err != nil {
		return err
	}
	cp := filepath.Join(s.Dir, "users")
	return os.MkdirAll(cp, 0700)
}

func (p *InitAccountParams) WriteJwt() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	c := jwt.NewAccountClaims(p.publicKey)
	c.Name = p.name
	d, err := c.Encode(p.kp)
	if err != nil {
		return err
	}

	fn := filepath.Join(s.Dir, fmt.Sprintf("%s.jwt", p.name))
	return ioutil.WriteFile(fn, []byte(d), 0666)
}
