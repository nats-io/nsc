/*
 * Copyright 2019 The NATS Authors
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
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/nats-io/nuid"
	"github.com/spf13/cobra"
)

func init() {
	GetRootCmd().AddCommand(createFixCmd())
}

type FixCmd struct {
	in        []string
	out       string
	creds     bool
	operators int
	accounts  int
	users     int
	nkeys     int

	Keys              map[string]string
	KeyToPrincipalKey map[string]string
	Operators         map[string]*OT
}

type OT struct {
	OC         jwt.OperatorClaims
	Jwts       map[string]string
	Accounts   map[string]*jwt.AccountClaims
	ActToUsers map[string]jwt.StringList
}

func NewOT() *OT {
	var ot OT
	ot.Jwts = make(map[string]string)
	ot.Accounts = make(map[string]*jwt.AccountClaims)
	ot.ActToUsers = make(map[string]jwt.StringList)
	return &ot
}

func createFixCmd() *cobra.Command {
	var params FixCmd

	var cmd = &cobra.Command{
		Use:   "fix",
		Short: "rebuilds a project tree from jwts, nk and cred files found in the input directories",
		Example: `nsc fix --in <dir>,<dir2>,<dir3> --out <outdir>
nsc fix --in <dir> --in <dir2> --out <outdir>

If you have user cred files, you can read user JWTs and nkeys from them by 
specifying the --creds option:

nsc fix --creds --in <dir> --out <outdir>

If successful, it will place jwts into <outdir>/operators and nkeys into 
<outdir>/keys. You can then define the NKEYS_PATH environment, and cd to 
the directory:

> export NKEYS_PATH=<outdir>/keys
> cd <outdir>/operators
> nsc list operators

Cases that won't be handled correctly include importing from multiple 
directories where user JWTs or cred files have the same user name, 
but different user keys issued by the same account. The last issued
cred or user jwt will win.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunStoreLessAction(cmd, args, &params); err != nil {
				return err
			}
			if params.operators > 0 {
				cmd.Printf("stored %d operators\n", params.operators)
				cmd.Printf("stored %d accounts\n", params.accounts)
				cmd.Printf("stored %d users\n", params.users)
				cmd.Printf("stored %d nkeys\n", params.nkeys)
				cmd.Println()
				if params.nkeys > 0 {
					cmd.Printf("export NKEYS_PATH=%s\n", filepath.Join(params.out, "keys"))
					cmd.Printf("cd %s\n", filepath.Join(params.out, "operators"))
				} else {
					cmd.Printf("cd %s\n", filepath.Join(params.out, "operators"))
				}
				cmd.Println("nsc list operators")
			}
			return nil
		},
		Hidden: true,
	}

	cmd.Flags().StringSliceVarP(&params.in, "in", "", nil, "input paths")
	cmd.Flags().StringVarP(&params.out, "out", "", "", "output dir")
	cmd.Flags().BoolVarP(&params.creds, "creds", "", false, "import creds")
	cmd.MarkFlagRequired("in")

	return cmd
}

func (p *FixCmd) SetDefaults(ctx ActionCtx) error {
	p.Keys = make(map[string]string)
	p.KeyToPrincipalKey = make(map[string]string)
	p.Operators = make(map[string]*OT)
	return nil
}

func (p *FixCmd) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *FixCmd) Load(ctx ActionCtx) error {
	return nil
}

func (p *FixCmd) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *FixCmd) Validate(ctx ActionCtx) error {
	return nil
}

func (p *FixCmd) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	rr := store.NewReport(store.OK, "")
	// Load all the keys
	kr, err := p.LoadNKeys(ctx)
	rr.Add(kr)
	if err != nil {
		return rr, err
	}

	lr, err := p.LoadOperators(ctx)
	rr.Add(lr)
	if err != nil {
		return rr, err
	}

	ar, err := p.LoadAccounts(ctx)
	rr.Add(ar)
	if err != nil {
		return rr, err
	}

	ur, err := p.LoadUsers(ctx)
	rr.Add(ur)
	if err != nil {
		return rr, err
	}

	if p.creds {
		cr, err := p.LoadCreds(ctx)
		rr.Add(cr)
		if err != nil {
			return rr, err
		}
	}

	if len(p.Operators) == 0 {
		return nil, fmt.Errorf("no operator found")
	}

	if err := p.Regenerate(rr); err != nil {
		return rr, err
	}

	return rr, nil
}

func (p *FixCmd) Regenerate(rr *store.Report) error {
	if p.out == "" {
		p.out = fmt.Sprintf("./fix_%s", nuid.Next())
	}
	var err error
	p.out, err = Expand(p.out)
	if err != nil {
		rr.AddError("error expanding destination directory %#q: %v", p.out, err)
		return err
	}
	if err := os.MkdirAll(p.out, 0700); err != nil {
		rr.AddError("error creating destination directory %#q: %v", p.out, err)
		return err
	}
	if err := os.Setenv(store.NKeysPathEnv, filepath.Join(p.out, "keys")); err != nil {
		rr.AddError("error setting env $%s=%s: %v", store.NKeysPathEnv, p.out, err)
		return err
	}

	gr := store.NewReport(store.OK, "Generate")
	rr.Add(gr)

	for _, ot := range p.Operators {
		name := ot.OC.Name
		if strings.Contains(name, " ") {
			ops, err := GetWellKnownOperators()
			if err == nil {
				for _, o := range ops {
					if strings.HasPrefix(o.AccountServerURL, ot.OC.AccountServerURL) {
						name = o.Name
						break
					}
				}
			}
		}
		or := store.NewReport(store.OK, "operator %s [%s]", name, ot.OC.Subject)
		gr.Add(or)

		keys := []string{ot.OC.Subject}
		keys = append(keys, ot.OC.SigningKeys...)

		var nk store.NamedKey
		nk.Name = name
		for _, k := range keys {
			kp := p.kp(k)
			if kp != nil {
				nk.KP = *kp
				break
			}
		}

		ks := store.NewKeyStore(nk.Name)
		s, err := store.CreateStore(nk.Name, filepath.Join(p.out, "operators"), &nk)
		if err != nil {
			or.AddError("error creating store: %v", err)
			continue
		}

		if err := s.StoreRaw([]byte(ot.Jwts[ot.OC.Subject])); err != nil {
			or.AddError("error storing: %v", err)
			continue
		}
		p.operators++

		for _, sk := range keys {
			skp := p.kp(sk)
			if skp != nil {
				_, err := ks.Store(*skp)
				if err != nil {
					or.AddError("error storing key %s: %v", sk, err)
					continue
				}
				or.AddOK("stored key %s", sk)
				p.nkeys++
			}
		}
		or.AddOK("stored operator")

		for ak, ac := range ot.Accounts {
			ar := store.NewReport(store.OK, "account %s [%s]", ac.Name, ac.Subject)
			or.Add(ar)

			atok := ot.Jwts[ak]
			if err := s.StoreRaw([]byte(atok)); err != nil {
				ar.AddError("error storing: %v", err)
				continue
			}
			ar.AddOK("stored account")
			p.accounts++

			akeys := []string{ac.Subject}
			akeys = append(akeys, ac.SigningKeys...)

			for _, k := range akeys {
				kp := p.kp(k)
				if kp != nil {
					_, err := ks.Store(*kp)
					if err != nil {
						ar.AddError("error storing key %s: %v", ak, err)
					}
					or.AddOK("stored key %s", k)
					p.nkeys++
				}
			}

			for _, uk := range ot.ActToUsers[ac.Subject] {
				utok := ot.Jwts[uk]
				uc, _ := jwt.DecodeUserClaims(utok)

				ur := store.NewReport(store.OK, "user %s [%s]", uc.Name, uk)
				ar.Add(ur)
				if err := s.StoreRaw([]byte(utok)); err != nil {
					ur.AddError("error storing user: %v", err)
					continue
				}
				p.users++

				ukp := p.kp(uk)
				if ukp != nil {
					_, err := ks.Store(*ukp)
					if err != nil {
						ur.AddError("error storing user key: %v", err)
						continue
					}
					or.AddOK("stored key %s", uk)
					p.nkeys++

					d, err := GenerateConfig(s, ac.Name, uc.Name, *ukp)
					if err != nil {
						ur.AddError("error generating creds file: %v", err)
						continue
					}
					cfp, err := ks.MaybeStoreUserCreds(ac.Name, uc.Name, d)
					if err != nil {
						ur.AddError("error storing creds file: %v", err)
						continue
					}
					ur.AddOK("stored creds file %s", cfp)
				}
			}
		}
	}
	return nil
}

func (p *FixCmd) kp(k string) *nkeys.KeyPair {
	if p.Keys[k] != "" {
		kp, err := nkeys.FromSeed([]byte(p.Keys[k]))
		if err != nil {
			return nil
		}
		return &kp
	}
	return nil
}

func (p *FixCmd) LoadNKeys(ctx ActionCtx) (*store.Report, error) {
	r := store.NewReport(store.OK, "Find NKeys")

	var err error
	for _, fp := range p.in {
		fp, err = Expand(fp)
		if err != nil {
			r.AddWarning("error expanding %s: %v", fp, err)
			continue
		}
		err := filepath.Walk(fp, func(src string, info os.FileInfo, err error) error {
			if info == nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(src)
			if ext == store.NKeyExtension {
				if err := p.LoadNKey(src); err != nil {
					r.AddFromError(err)
				}
			}

			return nil
		})
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

func (p *FixCmd) LoadOperators(ctx ActionCtx) (*store.Report, error) {
	sr := store.NewReport(store.OK, "Find Operators")
	var err error
	for _, fp := range p.in {
		fp, err = Expand(fp)
		if err != nil {
			sr.AddWarning("error expanding %s: %v", fp, err)
			continue
		}
		err := filepath.Walk(fp, func(src string, info os.FileInfo, err error) error {
			if info == nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(src)
			switch ext {
			case ".jwt":
				oc, tok, err := p.ReadOperatorJwt(src)
				if err != nil {
					sr.AddWarning("error loading %s: %v", src, err)
				}
				if oc != nil {
					or := store.NewReport(store.OK, "operator %s", oc.Subject)
					sr.Add(or)
					ot := p.Operators[oc.Subject]
					if ot == nil {
						ot = NewOT()
						p.Operators[oc.Subject] = ot
						ot.OC = *oc
						ot.Jwts[oc.Subject] = tok
						p.KeyToPrincipalKey[ot.OC.Subject] = ot.OC.Subject
						or.AddOK("loaded from %s", src)
					} else if oc.IssuedAt > ot.OC.IssuedAt {
						ot.OC = *oc
						ot.Jwts[oc.Subject] = tok
						or.AddOK("updated from %s", src)
					} else {
						or.AddOK("ignoring older config %s", src)
						return nil
					}
					for _, sk := range ot.OC.SigningKeys {
						p.KeyToPrincipalKey[sk] = ot.OC.Subject
					}
				}
			}
			return nil
		})
		if err != nil {
			return sr, err
		}
	}
	return sr, nil
}

func (p *FixCmd) LoadAccounts(ctx ActionCtx) (*store.Report, error) {
	sr := store.NewReport(store.OK, "Find Accounts")
	var err error
	for _, fp := range p.in {
		fp, err = Expand(fp)
		if err != nil {
			sr.AddWarning("error expanding %s: %v", fp, err)
			continue
		}
		err := filepath.Walk(fp, func(src string, info os.FileInfo, err error) error {
			if info == nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(src)
			switch ext {
			case ".jwt":
				ac, tok, err := p.ReadAccountJwt(src)
				if err != nil {
					sr.AddWarning("error loading %s: %v", src, err)
				}
				if ac != nil {
					ar := store.NewReport(store.OK, "account %s", ac.Subject)
					sr.Add(ar)
					iss := p.KeyToPrincipalKey[ac.Issuer]
					ot := p.Operators[iss]
					if ot == nil {
						ar.AddWarning("operator %s was not found - ignoring account %s", ac.Issuer, src)
						return nil
					}
					oac := ot.Accounts[ac.Subject]
					if oac == nil {
						ot.Accounts[ac.Subject] = ac
						ot.Jwts[ac.Subject] = tok
						p.KeyToPrincipalKey[ac.Subject] = ac.Subject
						ar.AddOK("loaded from %s", src)
					} else if ac.IssuedAt > oac.IssuedAt {
						ot.Accounts[ac.Subject] = ac
						ot.Jwts[ac.Subject] = tok
						ar.AddOK("updated from %s", src)
					} else {
						ar.AddOK("ignoring older config %s", src)
						return nil
					}
					for _, sk := range ac.SigningKeys {
						p.KeyToPrincipalKey[sk] = ac.Subject
					}
				}
			}
			return nil
		})
		if err != nil {
			return sr, err
		}
	}
	return sr, nil
}

func (p *FixCmd) LoadUsers(ctx ActionCtx) (*store.Report, error) {
	sr := store.NewReport(store.OK, "Find Users")
	var err error
	for _, fp := range p.in {
		fp, err = Expand(fp)
		if err != nil {
			sr.AddWarning("error expanding %s: %v", fp, err)
			continue
		}
		err := filepath.Walk(fp, func(src string, info os.FileInfo, err error) error {
			if info == nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(src)
			switch ext {
			case ".jwt":
				uc, tok, err := p.ReadUserJwt(src)
				if err != nil {
					sr.AddWarning("error loading %s: %v", src, err)
				}
				if uc == nil {
					return nil
				}
				r := p.loadUser(uc, tok, src)
				sr.Add(r)
			}
			return nil
		})
		if err != nil {
			return sr, err
		}
	}
	return sr, nil
}

func (p *FixCmd) loadUser(uc *jwt.UserClaims, tok string, src string) *store.Report {
	if uc != nil {
		r := store.NewReport(store.OK, "user %s", uc.Subject)
		iss := uc.Issuer
		if uc.IssuerAccount != "" {
			iss = uc.IssuerAccount
		}

		foundOne := false
		for _, ot := range p.Operators {
			if ot.Accounts[iss] != nil {
				foundOne = true
				users, ok := ot.ActToUsers[iss]
				if !ok {
					users = jwt.StringList{}
				}
				users.Add(uc.Subject)
				ot.ActToUsers[iss] = users

				var ouc *jwt.UserClaims
				if ot.Jwts[uc.Subject] != "" {
					ouc, _ = jwt.DecodeUserClaims(ot.Jwts[uc.Subject])
				}
				if ouc == nil {
					ot.Jwts[uc.Subject] = tok
					p.KeyToPrincipalKey[uc.Subject] = uc.Subject
					r.AddOK("loaded from %s", src)
				} else if uc.IssuedAt > ouc.IssuedAt {
					ot.Jwts[uc.Subject] = tok
					r.AddOK("updated from %s", src)
				} else {
					r.AddOK("ignoring older config %s", src)
				}
			}
		}
		if !foundOne {
			r.AddWarning("account %s was not found - ignoring user %s", iss, src)
		}
		return r
	}
	return nil
}

func (p *FixCmd) LoadCreds(ctx ActionCtx) (*store.Report, error) {
	sr := store.NewReport(store.OK, "Find Creds")
	var err error
	for _, fp := range p.in {
		fp, err = Expand(fp)
		if err != nil {
			sr.AddWarning("error expanding %s: %v", fp, err)
			continue
		}
		err := filepath.Walk(fp, func(src string, info os.FileInfo, err error) error {
			if info == nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(src)
			switch ext {
			case store.CredsExtension:
				uc, tok, err := p.ReadUserJwt(src)
				if err != nil {
					sr.AddFromError(err)
				}
				if uc == nil {
					return nil
				}

				r := p.loadUser(uc, tok, src)
				sr.Add(r)

				if err := p.LoadNKey(src); err != nil {
					sr.AddFromError(err)
				}
			}
			return nil
		})
		if err != nil {
			return sr, err
		}
	}
	return sr, nil
}

func (p *FixCmd) loadFile(fp string) ([]byte, error) {
	fp, err := Expand(fp)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(fp)
}

func (p *FixCmd) loadJwt(fp string) (string, error) {
	d, err := p.loadFile(fp)
	if err != nil {
		return "", fmt.Errorf("error %#q: %v", fp, err)
	}
	return jwt.ParseDecoratedJWT(d)
}

func (p *FixCmd) ReadOperatorJwt(fp string) (*jwt.OperatorClaims, string, error) {
	tok, err := p.loadJwt(fp)
	if err != nil {
		return nil, "", err
	}
	gc, err := jwt.DecodeGeneric(tok)
	if err != nil {
		return nil, "", err
	}
	if gc.Type != jwt.OperatorClaim {
		return nil, "", nil
	}
	oc, err := jwt.DecodeOperatorClaims(tok)
	return oc, tok, err
}

func (p *FixCmd) ReadAccountJwt(fp string) (*jwt.AccountClaims, string, error) {
	tok, err := p.loadJwt(fp)
	if err != nil {
		return nil, "", err
	}
	gc, err := jwt.DecodeGeneric(tok)
	if err != nil {
		return nil, "", err
	}
	if gc.Type != jwt.AccountClaim {
		return nil, "", nil
	}

	ac, err := jwt.DecodeAccountClaims(tok)
	if err != nil {
		return nil, "", err
	}
	return ac, tok, nil
}

func (p *FixCmd) ReadUserJwt(fp string) (*jwt.UserClaims, string, error) {
	tok, err := p.loadJwt(fp)
	if err != nil {
		return nil, "", err
	}
	gc, err := jwt.DecodeGeneric(tok)
	if err != nil {
		return nil, "", err
	}
	if gc.Type != jwt.UserClaim {
		return nil, "", nil
	}
	uc, err := jwt.DecodeUserClaims(tok)
	if err != nil {
		return nil, "", err
	}
	return uc, tok, nil
}

func (p *FixCmd) ReadGenericJwt(fp string) (*jwt.GenericClaims, error) {
	tok, err := p.loadJwt(fp)
	if err != nil {
		return nil, err
	}
	return jwt.DecodeGeneric(tok)
}

func (p *FixCmd) LoadNKey(fp string) error {
	d, err := p.loadFile(fp)
	if err != nil {
		return err
	}
	kp, err := jwt.ParseDecoratedNKey(d)
	if err != nil {
		return fmt.Errorf("error parsing nkey %#q: %v", fp, err)
	}

	pk, err := kp.PublicKey()
	if err != nil {
		return fmt.Errorf("error reading public key %#q: %v", fp, err)
	}
	sk, err := kp.Seed()
	if err != nil {
		return fmt.Errorf("error reading seed %#q: %v", fp, err)
	}
	p.Keys[pk] = string(sk)
	return nil
}
