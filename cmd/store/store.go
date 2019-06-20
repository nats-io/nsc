/*
 *
 *  * Copyright 2018-2019 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
)

const Version = "1"
const NSCFile = ".nsc"

const Users = "users"
const Accounts = "accounts"
const Clusters = "clusters"
const Servers = "servers"

var standardDirs = []string{Accounts}

// Store is a directory that contains nsc assets
type Store struct {
	sync.Mutex
	Dir            string
	Info           Info
	DefaultAccount string
}

type Info struct {
	Managed         bool   `json:"managed"`
	EntityName      string `json:"name"`
	EnvironmentName string `json:"env"`
	Kind            string `json:"kind"`
	Version         string `json:"version"`
	LastUpdateCheck int64  `json:"last_update_check"`
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
			EntityName:      operator.Name,
			EnvironmentName: operator.Name,
			Version:         Version,
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
		return nil, fmt.Errorf("operator %q already exists in %q", operator.Name, operatorsDir)
	}

	if operator.KP != nil {
		token, err := s.createOperatorToken(operator)
		if err != nil {
			return nil, err
		}
		if err := s.StoreClaim([]byte(token)); err != nil {
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
		return nil, fmt.Errorf("error writing .nsc in %q: %v", s.Dir, err)
	}

	for _, d := range standardDirs {
		dp := s.resolve(d, "")
		if err = os.MkdirAll(dp, 0700); err != nil {
			return nil, fmt.Errorf("error creating %q: %v", dp, err)
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
	v.Name = operator.Name

	if nkeys.IsValidPublicOperatorKey(pub) {
		s.Info.Kind = jwt.OperatorClaim
		v.Type = jwt.OperatorClaim
	} else {
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
		return nil, fmt.Errorf("%q is not a valid configuration directory", dir)
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

// Has returns true if the specified asset exists
func (s *Store) Has(name ...string) bool {
	fp := s.resolve(name...)
	return s.has(fp)
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
		return nil, fmt.Errorf("error reading %q: %v", fp, err)
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

// Read reads the specified file name or subpath from the store
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

func (s *Store) StoreClaim(data []byte) error {
	// Decode the jwt to figure out where it goes
	gc, err := jwt.DecodeGeneric(string(data))
	if err != nil {
		return fmt.Errorf("invalid jwt: %v", err)
	}
	if gc.Name == "" {
		return errors.New("jwt claim doesn't have a name")
	}
	var path string
	switch gc.Type {
	case jwt.AccountClaim:
		path = filepath.Join(Accounts, gc.Name, JwtName(gc.Name))
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
				if c != nil && c.DidSign(uc) {
					account = i.Name()
					break
				}
			}
		}
		if account == "" {
			return fmt.Errorf("account with public key %q is not in the store", issuer)
		}
		path = filepath.Join(Accounts, account, Users, JwtName(gc.Name))
	case jwt.ServerClaim:
		issuer := gc.Issuer
		var cluster string
		infos, err := s.List(Clusters)
		if err != nil {
			return err
		}
		for _, i := range infos {
			if i.IsDir() {
				c, err := s.LoadClaim(Clusters, i.Name(), JwtName(i.Name()))
				if err != nil {
					return err
				}
				if c != nil {
					if c.Subject == issuer {
						cluster = i.Name()
						break
					}
				}
			}
		}
		if cluster == "" {
			return fmt.Errorf("cluster with public key %q is not in the store", issuer)
		}
		path = filepath.Join(Clusters, cluster, Servers, JwtName(gc.Name))
	case jwt.ClusterClaim:
		path = filepath.Join(Clusters, gc.Name, JwtName(gc.Name))
	case jwt.OperatorClaim:
		path = JwtName(gc.Name)
	default:
		return fmt.Errorf("unsuported store claim type: %s", gc.Type)
	}

	return s.Write(data, path)
}

func (s *Store) GetName() string {
	return s.Info.EntityName
}

func (s *Store) operatorJwtName() (string, error) {
	if s.Has(".nsc") {
		var t Info
		err := s.loadJson(&t, ".nsc")
		if err != nil {
			return "", err
		}
		return JwtName(t.EntityName), nil
	}
	return "", fmt.Errorf("'.nsc' file was not found")
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
	fn := JwtName(s.GetName())
	if s.Has(fn) {
		d, err := s.Read(fn)
		if err != nil {
			return nil, err
		}
		c, err := jwt.DecodeOperatorClaims(string(d))
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
}

func (s *Store) ReadAccountClaim(name string) (*jwt.AccountClaims, error) {
	if s.Has(Accounts, name, JwtName(name)) {
		d, err := s.Read(Accounts, name, JwtName(name))
		if err != nil {
			return nil, err
		}
		c, err := jwt.DecodeAccountClaims(string(d))
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
}

func (s *Store) ReadUserClaim(accountName string, name string) (*jwt.UserClaims, error) {
	if s.Has(Accounts, accountName, Users, JwtName(name)) {
		d, err := s.Read(Accounts, accountName, Users, JwtName(name))
		if err != nil {
			return nil, err
		}
		c, err := jwt.DecodeUserClaims(string(d))
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
}

func (s *Store) ReadClusterClaim(name string) (*jwt.ClusterClaims, error) {
	if s.Has(Clusters, name, JwtName(name)) {
		d, err := s.Read(Clusters, name, JwtName(name))
		if err != nil {
			return nil, err
		}
		c, err := jwt.DecodeClusterClaims(string(d))
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
}

func (s *Store) ReadServerClaim(clusterName string, name string) (*jwt.ServerClaims, error) {
	if s.Has(Clusters, clusterName, Servers, JwtName(name)) {
		d, err := s.Read(Clusters, clusterName, Servers, JwtName(name))
		if err != nil {
			return nil, err
		}
		c, err := jwt.DecodeServerClaims(string(d))
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, nil
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
			return nil, fmt.Errorf("error reading %s %q: %v", kind, dirs[0], err)
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
					return nil, fmt.Errorf("error reading %s %q: %v", kind, dirs[0], err)
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
	Cluster  Entity
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
	c.KeyStore = NewKeyStore(s.Info.EnvironmentName)

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

	// try to set a default cluster
	cc, err := s.LoadDefaultEntity(Clusters)
	if err != nil {
		return nil, err
	}
	if cc != nil {
		c.SetContext(cc.Name, cc.Subject)
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
		i, err := cli.PromptChoices("select account", name, accounts)
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
		i, err := cli.PromptChoices("select user", "", users)
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
	if err != nil {
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
