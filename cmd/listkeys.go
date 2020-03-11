/*
 * Copyright 2018-2019 The NATS Authors
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
	"os"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createListKeysCmd() *cobra.Command {
	var params ListKeysParams
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List operator, account and user keys in the current operator and account context",
		Long: `List operator, account and user keys in the current operator and account context.
Additional flags allow you to specify which types of keys to display. For example
the --operator shows the operator key, the --accounts show account keys, etc.

You can further limit the account and user displayed by specifying the 
--account and --user flags respectively. To list all keys specify 
the --all flag.

The --not-referenced flag displays all keys not relevant to the current 
operator, accounts and users. These keys may be referenced in a different 
operator context.

The --filter flag allows you to specify a few letters in a public key
and display only those keys that match provided the --operator, 
--accounts, and --user or --all flags match the key type.
`,
		Example: `nsc list keys
nsc list keys --all (same as specifying --operator --accounts --users)
nsc list keys --operator --not-referenced (shows all other operator keys)
nsc list keys --all --filter VSVMGA (shows all keys containing the filter)
nsc list keys --account A (changes the account context to the specified account)
`,
		Args:         MaxArgs(0),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.Operator, "operator", "o", false, "show operator keys")
	cmd.Flags().BoolVarP(&params.Accounts, "accounts", "a", false, "show account keys")
	cmd.Flags().BoolVarP(&params.Users, "users", "u", false, "show user keys")
	cmd.Flags().StringVarP(&params.Account, "account", "", "", "show specified account keys")
	cmd.Flags().StringVarP(&params.User, "user", "", "", "show specified user key")
	cmd.Flags().BoolVarP(&params.All, "all", "A", false, "show operator, accounts and users")
	cmd.Flags().StringVarP(&params.Filter, "filter", "f", "", "filter keys containing string")
	cmd.Flags().BoolVarP(&params.Unreferenced, "not-referenced", "", false, "shows keys that are not referenced in the current operator context")
	cmd.Flags().BoolVarP(&params.Seeds, "show-seeds", "S", false, "shows seed keys value")

	return cmd
}

func init() {
	listCmd.AddCommand(createListKeysCmd())
}

type ListKeysParams struct {
	Seeds bool
	KeyCollectorParams
	KS store.KeyStore
}

func (p *ListKeysParams) SetDefaults(ctx ActionCtx) error {
	p.KS = ctx.StoreCtx().KeyStore
	return p.KeyCollectorParams.SetDefaults(ctx)
}

func (p *ListKeysParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Validate(ctx ActionCtx) error {
	kdir := store.GetKeysDir()
	_, err := os.Stat(kdir)
	if os.IsNotExist(err) {
		return fmt.Errorf("keystore %#q does not exist", kdir)
	}
	if ctx.StoreCtx().Operator.Name == "" && !p.Unreferenced {
		return errors.New("operator is not set -- set an operator first or try --not-referenced to list all keys not in the context")
	}
	if p.Unreferenced && p.Seeds {
		return errors.New("specify one of --show-seeds or --not-referenced")
	}
	return nil
}

func (p *ListKeysParams) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	var keys Keys

	keys.KeyList, err = p.KeyCollectorParams.Run(ctx)
	keys.MessageFn = p.Report
	return keys, err
}

func (p *ListKeysParams) Report(ks Keys) string {
	if ks.Len() == 0 {
		return "no keys matched query"
	}
	if p.Seeds {
		return p.ReportSeeds(ks)
	}
	var hasUnreferenced bool
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Keys")
	table.AddHeaders("Entity", "Key", "Signing Key", "Stored")
	for _, k := range ks.KeyList {
		unreferenced := false
		if k.Name == "?" {
			hasUnreferenced = true
			unreferenced = true
		}
		sk := ""
		if k.Signing {
			sk = "*"
		}
		stored := ""
		if k.HasKey() {
			stored = "*"
		}
		if k.Invalid {
			stored = "BAD"
		}
		pad := ""
		if !unreferenced {
			switch k.ExpectedKind {
			case nkeys.PrefixByteAccount:
				pad = " "
			case nkeys.PrefixByteUser:
				pad = "  "
			}
		}
		n := fmt.Sprintf("%s%s", pad, k.Name)
		table.AddRow(n, k.Pub, sk, stored)
	}
	s := table.Render()
	if hasUnreferenced {
		s = fmt.Sprintf("%s[?] unreferenced key - may belong to a different operator context", s)
	}
	return s
}

func (p *ListKeysParams) ReportSeeds(ks Keys) string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Seeds Keys")
	table.AddHeaders("Entity", "Private Key", "Signing Key")
	for _, k := range ks.KeyList {
		sk := ""
		if k.Signing {
			sk = "*"
		}

		pad := ""
		switch k.ExpectedKind {
		case nkeys.PrefixByteAccount:
			pad = " "
		case nkeys.PrefixByteUser:
			pad = "  "
		}

		n := fmt.Sprintf("%s%s", pad, k.Name)
		if k.Invalid || k.KeyPath == "" {
			k.Pub = fmt.Sprintf("%s [!]", k.Pub)
		} else {
			seed, err := p.KS.GetSeed(k.Pub)
			if err != nil {
				k.Pub = fmt.Sprintf("%s [ERR]", k.Pub)
			} else {
				k.Pub = seed
			}
		}

		table.AddRow(n, k.Pub, sk)
	}
	s := table.Render()
	s = fmt.Sprintf("%s[ ! ] seed is not stored\n", s)
	s = fmt.Sprintf("%s[ERR] error reading seed\n", s)
	return s
}
