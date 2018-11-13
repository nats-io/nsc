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
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createInitCmd() *cobra.Command {
	var p InitParams
	cmd := &cobra.Command{
		Use:           "init",
		Short:         "init a configuration directory",
		Example:       "init --name mynats <dirpath>",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				p.dir = "."
			}
			if len(args) == 1 {
				p.dir = args[0]
			}

			if err := p.Validate(); err != nil {
				return err
			}

			if err := p.Run(); err != nil {
				return err
			}

			if p.keyPath != "" {
				cmd.Printf("Generated operator key - private key stored %q\n", p.keyPath)
			}

			if p.cluster.keyPath != "" {
				cmd.Printf("Generated cluster key - private key stored %q\n", p.cluster.keyPath)
			}

			if p.account.keyPath != "" {
				cmd.Printf("Generated account key - private key stored %q\n", p.account.keyPath)
			}

			cmd.Printf("Success! - created project directory %q\n", p.dir)

			return nil
		},
	}

	dname := "default"
	u, err := user.Current()
	if err == nil {
		if u.Username != "" {
			dname = u.Username
		} else if u.Name != "" {
			dname = u.Name
		}
	}

	defaultName := func(s string, role string) string {
		if s == "default" {
			return fmt.Sprintf("%s_%s", role, s)
		} else {
			return fmt.Sprintf("%s_%s", s, role)
		}
	}

	cmd.Flags().StringVarP(&p.name, "name", "n", "", "name for the configuration environment, if not specified uses <dirname>")
	cmd.Flags().StringVarP(&p.name, "operator-name", "", defaultName(dname, "operator"), "operator name")
	cmd.Flags().StringVarP(&p.keyPath, "operator-key", "", "", "operator keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.create, "create-operator", "", true, "create operator")

	cmd.Flags().StringVarP(&p.account.name, "account-name", "", defaultName(dname, "account"), "name for the operator")
	cmd.Flags().StringVarP(&p.account.keyPath, "account-key", "", "", "account keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.account.create, "create-account", "", true, "create an account")

	cmd.Flags().StringVarP(&p.user.name, "user-name", "", dname, "name for the user")
	cmd.Flags().StringVarP(&p.user.keyPath, "user-key", "", "", "user keypath or seed value (default generated)")

	cmd.Flags().StringVarP(&p.cluster.name, "cluster-name", "", defaultName(dname, "cluster"), "name for the cluster")
	cmd.Flags().StringVarP(&p.cluster.keyPath, "cluster-key", "", "", "cluster keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.cluster.create, "create-cluster", "", false, "create a cluster")

	cmd.Flags().StringVarP(&p.server.name, "server-name", "", defaultName(dname, "server"), "name for the server")
	cmd.Flags().StringVarP(&p.server.keyPath, "server-key", "", "", "server keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.server.create, "create-server", "", false, "create a server")

	cmd.Flags().MarkHidden("create-account")
	cmd.Flags().MarkHidden("create-operator")

	return cmd
}

func init() {
	rootCmd.AddCommand(createInitCmd())
}

type Container struct {
	create  bool
	name    string
	dir     string
	kp      nkeys.KeyPair
	keyPath string
	kind    nkeys.PrefixByte
}

func (e *Container) Valid() error {
	var err error
	if e.keyPath != "" {
		e.kp, err = store.ResolveKey(e.keyPath)
		if err != nil {
			return err
		}

		d, err := e.kp.PublicKey()
		if err != nil {
			return err
		}

		if !store.IsPublicKey(e.kind, d) {
			return fmt.Errorf("invalid %s key", store.KeyTypeLabel(e.kind))
		}
	} else {
		e.kp, err = store.CreateNKey(e.kind)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Container) StoreKeys(root string) error {
	if e.create && e.keyPath == "" {
		ks := store.NewKeyStore()
		if _, err := ks.Store(root, e.name, e.kp); err != nil {
			return err
		}
	}
	return nil
}

type InitParams struct {
	Container
	account Container
	cluster Container
	server  Container
	user    Container
}

func (p *InitParams) Validate() error {
	s, _ := getStore()
	if s != nil {
		return fmt.Errorf("%q is already a store", s.Dir)
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(p.dir) {
		p.dir = filepath.Join(dir, p.dir)
	}

	p.create = false
	stat, err := os.Stat(p.dir)
	if err != nil {
		if os.IsNotExist(err) {
			p.create = true
		} else {
			return err
		}
	}
	if !p.create {
		if !stat.IsDir() {
			return fmt.Errorf("%q is not a directory", p.dir)
		}

		files, err := ioutil.ReadDir(p.dir)
		if err != nil {
			return err
		}
		if len(files) > 0 {
			return fmt.Errorf("%q is not empty", p.dir)
		}
	}

	if p.name == "" {
		p.name = filepath.Base(p.dir)
	}

	p.kind = nkeys.PrefixByteOperator
	p.account.kind = nkeys.PrefixByteAccount
	p.cluster.kind = nkeys.PrefixByteCluster
	p.server.kind = nkeys.PrefixByteServer
	p.user.kind = nkeys.PrefixByteUser

	entities := []*Container{&p.Container, &p.account, &p.cluster, &p.server, &p.user}
	for _, e := range entities {
		if e.name == "" {
			e.name = p.name
		}
		if err := e.Valid(); err != nil {
			return err
		}
	}

	return nil
}

func (p *InitParams) Run() error {
	if p.create {
		if err := os.MkdirAll(p.dir, 0700); err != nil {
			return err
		}
	}

	entities := []Container{p.Container, p.account, p.cluster, p.server, p.user}
	for _, e := range entities {
		if err := e.StoreKeys(p.name); err != nil {
			return err
		}
	}

	s, err := store.CreateStore(p.dir, p.name, p.Container.kp)
	if err != nil {
		return err
	}

	// create the account
	apk, err := p.account.kp.PublicKey()
	if err != nil {
		return err
	}
	ac := jwt.NewAccountClaims(string(apk))
	ac.Name = p.account.name
	as, err := ac.Encode(p.Container.kp)
	if err != nil {
		return err
	}
	if err := s.Write([]byte(as), store.Accounts, p.account.name, fmt.Sprintf("%s.jwt", p.account.name)); err != nil {
		return err
	}

	// create the default user
	upk, err := p.user.kp.PublicKey()
	if err != nil {
		return err
	}
	uc := jwt.NewUserClaims(string(upk))
	uc.Name = p.user.name
	us, err := uc.Encode(p.account.kp)
	if err != nil {
		return err
	}
	if err := s.Write([]byte(us), store.Accounts, p.account.name, store.Users, fmt.Sprintf("%s.jwt", p.user.name)); err != nil {
		return err
	}

	if p.cluster.create {
		cpk, err := p.cluster.kp.PublicKey()
		if err != nil {
			return err
		}
		cc := jwt.NewGenericClaims(string(cpk))
		cc.Name = p.cluster.name
		cs, err := cc.Encode(p.Container.kp)
		if err != nil {
			return err
		}
		if err := s.Write([]byte(cs), store.Clusters, p.cluster.name, fmt.Sprintf("%s.jwt", p.cluster.name)); err != nil {
			return err
		}
	}

	if p.server.create {
		spk, err := p.server.kp.PublicKey()
		if err != nil {
			return err
		}
		sc := jwt.NewGenericClaims(string(spk))
		ss, err := sc.Encode(p.Container.kp)
		if err != nil {
			return err
		}
		if err := s.Write([]byte(ss), store.Clusters, p.cluster.name, store.Servers, fmt.Sprintf("%s.jwt", p.server.name)); err != nil {
			return err
		}
	}

	return nil
}
