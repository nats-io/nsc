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

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

const Version = "1"
const NSCFile = ".nsc"

const Users = "users"
const Accounts = "accounts"

var standardDirs = []string{Accounts}

var ErrNotExist = errors.New("resource does not exist")

// Store is a directory that contains nsc assets
type Store struct {
	sync.Mutex
	Dir            string
	Info           Info
	DefaultAccount string
}

type Info struct {
	Managed bool   `json:"managed"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

func underlyingError(err error) error {
	switch err := err.(type) {
	case *ResourceErr:
		return err.Err
	}
	return err
}

type ResourceErr struct {
	Kind     string
	Resource string
	Err      error
}

func NewResourceNotExistErr(kind string, name string) error {
	return &ResourceErr{Kind: kind, Resource: name, Err: ErrNotExist}
}

func NewAccountNotExistErr(name string) error {
	return NewResourceNotExistErr("account", name)
}

func NewUserNotExistErr(name string) error {
	return NewResourceNotExistErr("user", name)
}

func NewOperatorNotExistErr(name string) error {
	return NewResourceNotExistErr("operator", name)
}

func (e *ResourceErr) Error() string {
	extra := ""
	switch e.Kind {
	case "account":
		extra = " in the current operator"
	case "user":
		extra = " in the current account"
	}
	return fmt.Sprintf("%s %s does not exist%s", e.Kind, e.Resource, extra)
}

func IsNotExist(err error) bool {
	return underlyingError(err) == ErrNotExist
}

func (i *Info) String() string {
	d, err := json.Marshal(i)
	if err != nil {
		return fmt.Sprintf("error serializing store type: %v", err)
	}
	return string(d)
}

func SafeName(n string) string {
	n = strings.TrimSpace(n)
	return n
}

// CreateStore creates a new Store in the specified directory.
// CreateStore will create the necessary directories and store the public key.
func CreateStore(env string, operatorsDir string, operator *NamedKey) (*Store, error) {
	var err error

	root := filepath.Join(operatorsDir, operator.Name)
	s := &Store{
		Dir: root,
		Info: Info{
			Name:    operator.Name,
			Version: Version,
			Kind:    jwt.OperatorClaim,
		},
	}

	if _, err := os.Stat(root); os.IsNotExist(err) {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, err
		}
	}

	files, err := ioutil.ReadDir(root)
	if err != nil {
		return nil, err
	}

	if len(files) != 0 {
		return nil, fmt.Errorf("operator %q already exists in %#q", operator.Name, operatorsDir)
	}

	if operator.KP != nil {
		token, err := s.createOperatorToken(operator)
		if err != nil {
			return nil, err
		}
		// this is a local operator - so just write it
		if err := s.StoreRaw([]byte(token)); err != nil {
			return nil, fmt.Errorf("error writing operator jwt: %v", err)
		}
	} else {
		s.Info.Managed = true
	}

	d, err := json.Marshal(s.Info)
	if err != nil {
		return nil, fmt.Errorf("error serializing .nsc: %v", err)
	}
	if err := s.Write(d, NSCFile); err != nil {
		return nil, fmt.Errorf("error writing .nsc in %#q: %v", s.Dir, err)
	}

	for _, d := range standardDirs {
		dp := s.resolve(d, "")
		if err = os.MkdirAll(dp, 0700); err != nil {
			return nil, fmt.Errorf("error creating %#q: %v", dp, err)
		}
	}

	return s, nil
}

func (s *Store) createOperatorToken(operator *NamedKey) (string, error) {
	pub, err := operator.KP.PublicKey()
	if err != nil {
		return "", fmt.Errorf("error reading public key: %v", err)
	}

	var v = jwt.NewGenericClaims(string(pub))
	s.Info.Kind = jwt.OperatorClaim
	v.Name = operator.Name
	v.Type = jwt.OperatorClaim

	if !nkeys.IsValidPublicOperatorKey(pub) {
		return "", fmt.Errorf("unsupported key type %q - stores require operator nkeys", pub)
	}

	token, err := v.Encode(operator.KP)
	if err != nil {
		return "", err
	}

	return token, nil
}

// LoadStore loads a store from the specified directory path.
func LoadStore(dir string) (*Store, error) {
	sf := filepath.Join(dir, NSCFile)
	if _, err := os.Stat(sf); os.IsNotExist(err) {
		return nil, fmt.Errorf("%#q is not a valid configuration directory", dir)
	}

	s := &Store{Dir: dir}
	if err := s.loadJson(&s.Info, ".nsc"); err != nil {
		return nil, fmt.Errorf("error loading '.nsc' file: %v", err)
	}

	return s, nil
}

func (s *Store) IsManaged() bool {
	return s.Info.Managed
}

func (s *Store) resolve(name ...string) string {
	return filepath.Join(s.Dir, filepath.Join(name...))
}

func (s *Store) Resolve(name ...string) string {
	return filepath.Join(s.Dir, filepath.Join(name...))
}

// Has returns true if the specified asset exists
func (s *Store) Has(name ...string) bool {
	fp := s.resolve(name...)
	return s.has(fp)
}

func (s *Store) HasAccount(name string) bool {
	return s.Has(Accounts, name, JwtName(name))
}

func (s *Store) has(fp string) bool {
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		return false
	}
	return true
}

// Read reads the specified file name or subpath from the store
func (s *Store) Read(name ...string) ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	fp := s.resolve(name...)
	d, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("error reading %#q: %v", fp, err)
	}
	return d, nil
}

// Write writes the specified file name or subpath in the store
func (s *Store) Write(data []byte, name ...string) error {
	s.Lock()
	defer s.Unlock()

	fp := s.resolve(name...)
	dp := filepath.Dir(fp)

	if err := os.MkdirAll(dp, 0700); err != nil {
		return err
	}
	return ioutil.WriteFile(fp, data, 0600)
}

func (s *Store) List(path ...string) ([]os.FileInfo, error) {
	s.Lock()
	defer s.Unlock()

	fp := s.resolve(path...)
	return ioutil.ReadDir(fp)
}

// Delete the specified file name or subpath from the store
func (s *Store) Delete(name ...string) error {
	s.Lock()
	defer s.Unlock()
	fp := s.resolve(name...)
	return os.Remove(fp)
}

func (s *Store) ListSubContainers(name ...string) ([]string, error) {
	var containers []string
	fp := filepath.Join(name...)
	if s.Has(fp) {
		infos, err := s.List(fp)
		if err != nil {
			return nil, err
		}
		for _, i := range infos {
			if i.IsDir() {
				if s.Has(fp, i.Name(), JwtName(i.Name())) {
					containers = append(containers, i.Name())
				}
			}
		}
	}
	return containers, nil
}

func (s *Store) ListEntries(name ...string) ([]string, error) {
	var entries []string
	fp := filepath.Join(name...)
	if s.Has(fp) {
		infos, err := s.List(fp)
		if err != nil {
			return nil, err
		}
		for _, v := range infos {
			if !v.IsDir() && IsJwtName(v.Name()) {
				entries = append(entries, PlainName(v.Name()))
			}
		}
	}
	return entries, nil
}

func (s *Store) ClaimType(data []byte) (*jwt.ClaimType, error) {
	// Decode the jwt to figure out where it goes
	gc, err := jwt.DecodeGeneric(string(data))
	if err != nil {
		return nil, fmt.Errorf("invalid jwt: %v", err)
	}
	if gc.Name == "" {
		return nil, errors.New("jwt claim doesn't have a name")
	}
	return &gc.Type, nil
}

func PullAccount(u string) (Status, error) {
	c := &http.Client{Timeout: time.Second * 5}
	r, err := c.Get(u)
	if err != nil {
		return nil, fmt.Errorf("error pulling %q: %v", u, err)
	}
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %q: %v", u, err)
	}
	return PullReport(r.StatusCode, buf.Bytes()), nil
}

func PushAccount(u string, data []byte) (Status, error) {
	resp, err := http.Post(u, "application/jwt", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	message, err := ioutil.ReadAll(resp.Body)
	return PushReport(resp.StatusCode, message), err
}

func (s *Store) handleManagedAccount(data []byte) (*Report, error) {
	ac, err := jwt.DecodeAccountClaims(string(data))
	if err != nil {
		return nil, fmt.Errorf("error decoding account claim")
	}

	oc, err := s.ReadOperatorClaim()
	if err != nil {
		return nil, fmt.Errorf("unable to push to the operator - failed to read operator claim: %v", err)
	}
	if oc.AccountServerURL == "" {
		return nil, fmt.Errorf("unable to push to %q - operator doesn't set an account server url", oc.Name)
	}

	u, err := url.Parse(oc.AccountServerURL)
	if err != nil {
		return nil, fmt.Errorf("unable to push to the %q - failed to parse account server url (%q): %v", oc.Name, oc.AccountServerURL, err)
	}

	r := NewDetailedReport(false)
	r.Label = "synchronized account jwt with account server"
	// this is an url - join with path
	u.Path = path.Join(u.Path, "accounts", ac.Subject)
	push, err := PushAccount(u.String(), data)
	if err != nil {
		r.AddError("error pushing account %q: %v", ac.Name, err)
		return r, nil
	}
	r.Add(push)
	if push.Code() == OK {
		pull, err := PullAccount(u.String())
		if err != nil {
			r.AddError("error pulling account %q: %v", ac.Name, err)
		}
		r.Add(pull)
	}
	return r, nil
}

func (s *Store) StoreClaim(data []byte) (Status, error) {
	ct, err := s.ClaimType(data)
	if err != nil {
		return nil, err
	}
	if *ct == jwt.AccountClaim && s.IsManaged() {
		var pull Report
		var push Report
		pp, err := s.handleManagedAccount(data)
		if pp != nil {
			if len(pp.Details) >= 1 {
				push = *pp.Details[0].(*Report)
			}
			if len(pp.Details) >= 2 {
				pull = *pp.Details[1].(*Report)
			}
		}
		if err != nil {
			return pp, err
		}

		if pull.Code() == OK {
			// the pull succeeded so we have a JWT
			if err := s.StoreRaw(pull.Data); err != nil {
				pp.AddError("failed to store jwt: %v", err)
				return pp, err
			}
		} else if push.Code() == OK || push.Code() == WARN {
			// Push OK but failed pull, store self-signed
			if err := s.StoreRaw(data); err != nil {
				pp.AddError("failed to store self-signed jwt: %v", err)
				return pp, err
			}
		}
		return pp, nil
	} else {
		return nil, s.StoreRaw(data)
	}
}

func (s *Store) StoreRaw(data []byte) error {
	ct, err := s.ClaimType(data)
	if err != nil {
		return err
	}
	var path string
	switch *ct {
	case jwt.AccountClaim:
		ac, err := jwt.DecodeAccountClaims(string(data))
		if err != nil {
			return err
		}
		path = filepath.Join(Accounts, ac.Name, JwtName(ac.Name))
	case jwt.UserClaim:
		uc, err := jwt.DecodeUserClaims(string(data))
		if err != nil {
			return err
		}
		issuer := uc.Issuer
		if uc.IssuerAccount != "" {
			issuer = uc.IssuerAccount
		}
		var account string
		infos, err := s.List(Accounts)
		if err != nil {
			return err
		}
		for _, i := range infos {
			if i.IsDir() {
				c, err := s.ReadAccountClaim(i.Name())
				if err != nil {
					return err
				}
				if c.DidSign(uc) {
					account = i.Name()
					break
				}
			}
		}
		if account == "" {
			return fmt.Errorf("account with public key %q is not in the store", issuer)
		}
		path = filepath.Join(Accounts, account, Users, JwtName(uc.Name))
	case jwt.OperatorClaim:
		_, err := jwt.DecodeOperatorClaims(string(data))
		if err != nil {
			return err
		}
		path = JwtName(s.GetName())
	default:
		return fmt.Errorf("unsuported store claim type: %s", *ct)
	}

	return s.Write(data, path)
}

func (s *Store) GetName() string {
	return s.Info.Name
}

func JwtName(name string) string {
	return fmt.Sprintf("%s.jwt", SafeName(name))
}

func IsJwtName(name string) bool {
	return strings.HasSuffix(name, ".jwt")
}

func PlainName(name string) string {
	if strings.HasSuffix(name, ".jwt") {
		return name[:len(name)-4]
	}
	return name
}

func (s *Store) loadJson(v interface{}, name ...string) error {
	if s.Has(name...) {
		d, err := s.Read(name...)
		if err != nil {
			return err
		}
		err = json.Unmarshal(d, &v)
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}

func (s *Store) LoadClaim(name ...string) (*jwt.GenericClaims, error) {
	if s.Has(name...) {
		d, err := s.Read(name...)
		if err != nil {
			return nil, err
		}
		c, err := jwt.DecodeGeneric(string(d))
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
}

func (s *Store) ReadOperatorClaim() (*jwt.OperatorClaims, error) {
	d, err := s.ReadRawOperatorClaim()
	if err != nil {
		return nil, err
	}
	c, err := jwt.DecodeOperatorClaims(string(d))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) ReadRawOperatorClaim() ([]byte, error) {
	fn := JwtName(s.GetName())
	if s.Has(fn) {
		d, err := s.Read(fn)
		if err != nil {
			return nil, err
		}
		return d, nil
	}
	return nil, NewOperatorNotExistErr(s.GetName())
}

func (s *Store) ReadAccountClaim(name string) (*jwt.AccountClaims, error) {
	d, err := s.ReadRawAccountClaim(name)
	if err != nil {
		return nil, err
	}
	c, err := jwt.DecodeAccountClaims(string(d))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) ReadRawAccountClaim(name string) ([]byte, error) {
	if s.Has(Accounts, name, JwtName(name)) {
		d, err := s.Read(Accounts, name, JwtName(name))
		if err != nil {
			return nil, err
		}
		return d, nil
	}
	return nil, NewAccountNotExistErr(name)
}

func (s *Store) ReadUserClaim(accountName string, name string) (*jwt.UserClaims, error) {
	d, err := s.ReadRawUserClaim(accountName, name)
	if err != nil {
		return nil, err
	}
	c, err := jwt.DecodeUserClaims(string(d))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) ReadRawUserClaim(accountName string, name string) ([]byte, error) {
	if s.Has(Accounts, accountName, Users, JwtName(name)) {
		d, err := s.Read(Accounts, accountName, Users, JwtName(name))
		if err != nil {
			return nil, err
		}
		return d, nil
	}
	return nil, NewUserNotExistErr(name)
}

func (s *Store) LoadRootClaim() (*jwt.GenericClaims, error) {
	fn := JwtName(s.GetName())
	if s.Has(fn) {
		return s.LoadClaim(fn)
	}
	return nil, nil
}

func (s *Store) LoadDefaultEntity(kind string) (*jwt.GenericClaims, error) {
	dirs, err := s.ListSubContainers(kind)
	if err != nil {
		return nil, fmt.Errorf("error listing %s: %v", kind, err)
	}
	if len(dirs) == 1 {
		ac, err := s.LoadClaim(kind, dirs[0], JwtName(dirs[0]))
		if err != nil {
			return nil, fmt.Errorf("error reading %s %#q: %v", kind, dirs[0], err)
		}
		return ac, nil
	}

	pwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("unable to get pwd: %v", err)
	}

	for _, n := range dirs {
		tp := filepath.Join(s.Dir, kind, n)
		if strings.HasPrefix(pwd, tp) {
			if s.Has(kind, filepath.Base(pwd), JwtName(filepath.Base(pwd))) {
				ac, err := s.LoadClaim(kind, filepath.Base(pwd), JwtName(filepath.Base(pwd)))
				if err != nil {
					return nil, fmt.Errorf("error reading %s %#q: %v", kind, dirs[0], err)
				}
				return ac, nil
			} else {
				continue
			}
		}
	}
	return nil, nil
}

func (s *Store) GetRootPublicKey() (string, error) {
	c, err := s.LoadRootClaim()
	if err != nil {
		return "", err
	}
	if c != nil {
		return c.Subject, nil
	}
	return "", nil
}

type Entity struct {
	Name      string
	PublicKey string
}

type Context struct {
	Operator Entity
	Account  Entity
	KeyStore KeyStore
	Store    *Store
}

func (ctx *Context) SetContext(name string, pub string) error {
	kp, err := nkeys.FromPublicKey(pub)
	if err != nil {
		return fmt.Errorf("error parsing public key: %v", err)
	}
	pre, err := KeyType(kp)
	if err != nil {
		return err
	}

	var e *Entity
	switch pre {
	case nkeys.PrefixByteOperator:
		e = &ctx.Operator
	case nkeys.PrefixByteAccount:
		e = &ctx.Account
	}

	if e != nil {
		e.Name = name
		e.PublicKey = pub
	}

	return nil
}

func (s *Store) GetContext() (*Context, error) {
	var c Context
	var err error

	c.Store = s
	c.KeyStore = NewKeyStore(s.Info.Name)

	root, err := s.LoadRootClaim()
	if err != nil {
		return nil, fmt.Errorf("error reading root: %v", err)
	}

	if root != nil {
		if err = c.SetContext(root.Name, root.Subject); err != nil {
			return nil, err
		}
	}

	// try to set a default account
	var ac *jwt.GenericClaims

	if s.DefaultAccount != "" {
		ac, err = s.LoadClaim(Accounts, s.DefaultAccount, JwtName(s.DefaultAccount))
	} else {
		ac, err = s.LoadDefaultEntity(Accounts)
	}

	if err != nil {
		return nil, err
	}
	if ac != nil {
		c.SetContext(ac.Name, ac.Subject)
	}
	return &c, nil
}

func (ctx *Context) ResolveKey(kind nkeys.PrefixByte, flagValue string) (nkeys.KeyPair, error) {
	kp, err := ResolveKey(flagValue)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		var pk string
		switch kind {
		case nkeys.PrefixByteAccount:
			pk = ctx.Account.PublicKey
		case nkeys.PrefixByteOperator:
			pk = ctx.Operator.PublicKey
		default:
			return nil, fmt.Errorf("unsupported key %d resolution", kind)
		}
		// don't try to resolve empty
		if pk != "" {
			kp, err = ctx.KeyStore.GetKeyPair(pk)
			if err != nil {
				return nil, err
			}
		}
		// not found
		if kp == nil {
			return nil, nil
		}
	}
	if !KeyPairTypeOk(kind, kp) {
		return nil, fmt.Errorf("unexpected resolved keytype type")
	}
	return kp, nil
}

func (ctx *Context) PickAccount(name string) (string, error) {
	if name == "" {
		name = ctx.Account.Name
	}

	accounts, err := ctx.Store.ListSubContainers(Accounts)
	if err != nil {
		return "", err
	}
	if len(accounts) == 0 {
		return "", fmt.Errorf("no accounts defined - add one first")
	}
	if len(accounts) == 1 {
		name = accounts[0]
	}
	if len(accounts) > 1 {
		i, err := cli.Select("select account", name, accounts)
		if err != nil {
			return "", err
		}
		name = accounts[i]
	}

	// allow downstream use of context to have account
	ctx.Account.Name = name

	return name, nil
}

// Returns an user name for the account if there's only one user
func (ctx *Context) DefaultUser(accountName string) *string {
	users, err := ctx.Store.ListEntries(Accounts, accountName, Users)
	if err != nil {
		return nil
	}
	if len(users) == 1 {
		return &users[0]
	}
	return nil
}

func (ctx *Context) PickUser(accountName string) (string, error) {
	var err error
	if accountName == "" {
		accountName = ctx.Account.Name
	}

	if accountName == "" {
		accountName, err = ctx.PickAccount(accountName)
		if err != nil {
			return "", err
		}
	}
	// allow downstream use of context to have account
	ctx.Account.Name = accountName

	users, err := ctx.Store.ListEntries(Accounts, accountName, Users)
	if err != nil {
		return "", err
	}
	if len(users) == 0 {
		return "", fmt.Errorf("account %q doesn't have any users - add one first", accountName)
	}
	if len(users) == 1 {
		return users[0], nil
	}
	if len(users) > 1 {
		i, err := cli.Select("select user", "", users)
		if err != nil {
			return "", err
		}
		return users[i], nil
	}
	return "", nil
}

// GetAccountKeys returns the public keys for the named account followed
// by its signing keys
func (ctx *Context) GetAccountKeys(name string) ([]string, error) {
	var keys []string
	ac, err := ctx.Store.ReadAccountClaim(name)
	if err != nil && !IsNotExist(err) {
		return nil, err
	}
	if ac == nil {
		// not found
		return nil, nil
	}
	keys = append(keys, ac.Subject)
	keys = append(keys, ac.SigningKeys...)
	return keys, nil
}

// GetOperatorKeys returns the public keys for the operator
// followed by its signing keys
func (ctx *Context) GetOperatorKeys() ([]string, error) {
	var keys []string
	oc, err := ctx.Store.ReadOperatorClaim()
	if err != nil {
		return nil, err
	}
	if oc == nil {
		// not found
		return nil, nil
	}
	keys = append(keys, oc.Subject)
	keys = append(keys, oc.SigningKeys...)
	return keys, nil
}
