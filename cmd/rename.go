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
	"errors"
	"fmt"
	"os"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

var renameCmd = &cobra.Command{
	Use: "rename",
	Short: "Rename operator, account or user",
	Hidden: true,
}

func init() {
	GetRootCmd().AddCommand(renameCmd)
	renameCmd.AddCommand(createRenameAccountCmd())
}

func createRenameAccountCmd() *cobra.Command {
	var params RenameAccountParams

	var cmd = &cobra.Command{
		Use: "account",
		Short: "renames an account",
		Args: cobra.ExactArgs(2),
		SilenceUsage: true,
		Example: "nsc rename account <name> <newname>",
		RunE: func(cmd *cobra.Command, args []string) error {
			params.from = args[0]
			params.to = args[1]
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().BoolVarP(&params.yes, "OK", "", false, "backed up")
	cmd.Flag("OK").Hidden = true

	return cmd
}

type RenameAccountParams struct {
	SignerParams
	from string
	to   string
	ac   *jwt.AccountClaims
	yes bool
}

func (p *RenameAccountParams) SetDefaults(ctx ActionCtx) error {
	if !p.yes {
		conf := GetConfig()
		stores := AbbrevHomePaths(conf.StoreRoot)
		keys := AbbrevHomePaths(store.GetKeysDir())
		ctx.CurrentCmd().Print("This command makes destructive changes to files and keys.\n")
		ctx.CurrentCmd().Printf("Please backup:\n\t%s\n\t%s\n", stores, keys)
		ctx.CurrentCmd().Printf("And rerun this command with --OK\n")
		return errors.New("override flag is required")
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *RenameAccountParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *RenameAccountParams) Load(ctx ActionCtx) error {
	var err error
	p.ac, err = ctx.StoreCtx().Store.ReadAccountClaim(p.from)
	return err
}

func (p *RenameAccountParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *RenameAccountParams) Validate(ctx ActionCtx) error {
	bc, err := ctx.StoreCtx().Store.ReadAccountClaim(p.to)
	if err == nil || bc != nil {
		return fmt.Errorf("account %q already exists", p.to)
	}
	cdir := ctx.StoreCtx().KeyStore.CalcAccountCredsDir(p.to)
	if _, err := os.Stat(cdir); os.IsExist(err) {
		return fmt.Errorf("creds dir %q already exists", cdir)
	}
	return p.SignerParams.Resolve(ctx)
}

func (p *RenameAccountParams) copyAccount(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(false)

	p.ac.Name = p.to
	token, err := p.ac.Encode(p.signerKP)
	if err != nil {
		r.AddError("error encoding JWT: %v", err)
		return r, err
	}
	StoreAccountAndUpdateStatus(ctx, token, r)
	s := ctx.StoreCtx().Store

	if s.IsManaged() {
		bc, err := s.ReadAccountClaim(p.to)
		if err != nil {
			r.AddError("unable to read account %q: %v", p.to, err)
			return r, err
		} else {
			r.Add(DiffAccountLimits(p.ac, bc))
		}
	}
	r.AddOK("copied account %q to %q", p.from, p.to)
	return r, nil
}

func (p *RenameAccountParams) copyUsers(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(false)
	s := ctx.StoreCtx().Store
	users, err := s.ListEntries(store.Accounts, p.from, store.Users)
	if err != nil {
		r.AddError("error listing users: %v", err)
		return r, err
	}
	for _, u := range users {
		s, _ := p.moveUser(ctx, u)
		r.Add(s)
	}
	if err := s.Delete(store.Accounts, p.from, store.Users); err != nil {
		r.AddWarning("error deleting user directory from account %q", p.from)
	} else {
		r.AddOK("deleted user directory from account %q", p.from)
	}
	if err := s.Delete(store.Accounts, p.from, store.JwtName(p.from)); err != nil {
		r.AddWarning("error deleting account %q jwt", p.from)
	} else {
		r.AddOK("deleted account %q jwt", p.from)
	}
	if err := s.Delete(store.Accounts, p.from); err != nil {
		r.AddWarning("error deleting account %q dir: %v", p.from, err)
	} else {
		r.AddOK("deleted account directory %q", p.from)
	}
	return r, nil
}

func (p *RenameAccountParams) moveUser(ctx ActionCtx, u string) (store.Status, error) {
	r := store.NewDetailedReport(false)
	s := ctx.StoreCtx().Store
	d, err := s.ReadRawUserClaim(p.from, u)
	if err != nil {
		r.AddError("Unable to read user %q: %v", u, err)
		return r, err
	}

	if err := s.Write(d, store.Accounts, p.to, store.Users, store.JwtName(u)); err != nil {
		r.AddError("Unable to write user %q: %v", u, err)
		return r, err
	}
	r.AddOK("copied user %q to account %q", u, p.to)
	if err := s.Delete(store.Accounts, p.from, store.Users, store.JwtName(u)); err != nil {
		r.AddWarning("error deleting user %q from account %q", u, p.from)
	}
	return r, err
}

func (p *RenameAccountParams) moveCreds(ctx ActionCtx, u string) (store.Status, error) {
	r := store.NewDetailedReport(false)
	fp := ctx.StoreCtx().KeyStore.CalcAccountCredsDir(p.from)
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		r.AddOK("creds directory for %q doesn't exist", p.from)
		return r, nil
	}
	tfp := ctx.StoreCtx().KeyStore.CalcAccountCredsDir(p.to)
	if err := os.Rename(fp, tfp); err != nil {
		r.AddError("error renaming creds dir %q: %v", tfp, err)
		return r, err
	}
	r.AddOK("renamed creds dir for account %q to %q", p.from, p.to)
	return r, nil
}

func (p *RenameAccountParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	r.ReportSum = false

	sr, err := p.copyAccount(ctx)
	r.Add(sr)
	if err != nil {
		return r, err
	}
	cus, err := p.copyUsers(ctx)
	r.Add(cus)

	if r.HasNoErrors() {
		r.AddOK("copied account %q and renamed to %q", p.from, p.to)
	}
	return r, err
}
