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

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

// the keyfile name
const DefaultDirName = ".ncs"
const DataHomeEnv = "NSC_HOME"
const DataProfileEnv = "NSC_PROFILE"
const DefaultProfile = "default"
const KeyName = "account_priv.key"
const AccountActivation = "account_activation"
const Activations = "activations"
const Users = "users"
const Exports = "exports"
const Imports = "imports"
const Tokens = "tokens"

// Store is a directory that contains nsc assets
type Store struct {
	sync.Mutex
	Dir     string
	Profile string
	Index   *Index
}

func NewStore(dir string, profile string) *Store {
	var s Store
	s.Dir = dir
	s.Profile = profile
	s.Index = NewIndex(&s)
	return &s
}

func Home(storeHomeDir string) (string, error) {
	if storeHomeDir == "" {
		storeHomeDir = os.Getenv(DataHomeEnv)
		if storeHomeDir == "" {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			storeHomeDir = filepath.Join(u.HomeDir, DefaultDirName)
		}
	}
	return storeHomeDir, nil
}

func Profile(profile string) string {
	if profile == "" {
		profile = os.Getenv(DataProfileEnv)
		if profile == "" {
			profile = DefaultProfile
		}
	}
	return profile
}

// ListProfiles returns the names of profiles found in the specified directory
// if no directory is specified, the function will try to obtain it from
// $NSC_HOME environment variable. If $NSC_HOME is not defined, then the ~/.nsc
// is used
func ListProfiles(dir string) ([]string, error) {
	dir, err := Home(dir)
	if err != nil {
		return nil, err
	}

	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	profiles := make([]string, 0)
	for _, i := range infos {
		if i.IsDir() {
			p := filepath.Join(dir, i.Name(), KeyName)
			if _, err = os.Stat(p); err == nil {
				profiles = append(profiles, i.Name())
			}
		}
	}
	return profiles, nil
}

// LoadStore loads a store from the specified directory path and profile name.
// If not specified, $NSC_HOME or ~/.nsc will be attempted. If a profile name
// is not provided, $NSC_PROFILE or "default" will be attempted.
func LoadStore(storeHomeDir string, profile string) (*Store, error) {
	home, err := Home(storeHomeDir)
	if err != nil {
		return nil, err
	}

	profile = Profile(profile)

	dir := filepath.Join(home, profile)
	t := filepath.Join(dir, KeyName)

	if _, err := os.Stat(t); os.IsNotExist(err) {
		return nil, err
	}

	return NewStore(home, profile), nil
}

// CreateStore creates a new Store in the specified directory or $NSC_HOME environment variable
// or ~/.nsc. If profile is is not specified it will $NSC_PROFILE or "default" will be attempted.
// CreateStore will create the necessary directories and store the private key from KeyPair.
func CreateStore(storeHomeDir string, profile string, kp nkeys.KeyPair) (*Store, error) {
	if kp == nil {
		return nil, errors.New("keypair is required")
	}
	var err error
	storeHomeDir, err = Home(storeHomeDir)
	if err != nil {
		return nil, err
	}

	profile = Profile(profile)

	dir := filepath.Join(storeHomeDir, profile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}

	s := NewStore(storeHomeDir, profile)
	kd, err := kp.Seed()
	if err != nil {
		return nil, err
	}

	if err := s.Write(KeyName, []byte(kd)); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s.Index != nil {
		return s.Index.Close()
	}
	return nil
}

func (s *Store) FilePath(name string) string {
	return filepath.Join(s.Dir, s.Profile, name)
}

// Write writes the specified file name or subpath in the store
func (s *Store) Write(name string, data []byte) error {
	s.Lock()
	defer s.Unlock()

	fp := filepath.Join(s.Dir, s.Profile, name)
	dp := filepath.Dir(fp)
	if err := os.MkdirAll(dp, 0700); err != nil {
		return err
	}
	return ioutil.WriteFile(fp, data, 0600)
}

func (s *Store) WriteEntry(name string, entry interface{}) error {
	data, err := json.MarshalIndent(entry, "", " ")
	if err != nil {
		return err
	}
	return s.Write(name, data)
}

// Has returns true if the specified asset exists
func (s *Store) Has(name string) bool {
	fp := filepath.Join(s.Dir, s.Profile, name)
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		return false
	}
	return true
}

// Read reads the specified file name or subpath from the store
func (s *Store) Read(name string) ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	fp := filepath.Join(s.Dir, s.Profile, name)
	return ioutil.ReadFile(fp)
}

// Read reads the specified file name or subpath from the store
func (s *Store) Delete(name string) error {
	s.Lock()
	defer s.Unlock()
	fp := filepath.Join(s.Dir, s.Profile, name)
	return os.Remove(fp)
}

func (s *Store) ReadEntry(name string, entry interface{}) error {
	data, err := s.Read(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, entry)
}

// Returns the public key stored in the store
func (s *Store) GetPublicKey() (string, error) {
	pk, err := s.GetKey()
	if err != nil {
		return "", err
	}
	k, err := pk.PublicKey()
	if err != nil {
		return "", err
	}
	return string(k), nil
}

// Returns the public key stored in the store
func (s *Store) GetKey() (nkeys.KeyPair, error) {
	d, err := s.Read(KeyName)
	if err != nil {
		return nil, err
	}
	pk, err := nkeys.FromSeed(d)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func (s *Store) GetAccountActivation() (string, error) {
	d, err := s.Read(AccountActivation)
	if err != nil {
		return "", err
	}
	return string(d), nil
}

func (s *Store) SetAccountActivation(token string) error {
	return s.Write(AccountActivation, []byte(token))
}

func (s *Store) List(subDir string, ext string) ([]string, error) {
	s.Lock()
	defer s.Unlock()

	names := make([]string, 0)
	dir := filepath.Join(s.Dir, s.Profile, subDir)

	if !s.Has(subDir) {
		return nil, nil
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != dir {
			return filepath.SkipDir
		}

		if info.IsDir() && path == dir {
			return nil
		}

		if strings.HasSuffix(info.Name(), ext) {
			names = append(names, info.Name())
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error listing %q: %v", dir, err)
	}
	return names, nil
}

func (s *Store) WriteToken(token string, tag ...Tag) error {
	c, err := jwt.DecodeGeneric(token)
	if err != nil {
		return err
	}

	var t Token
	t.Data = token

	if c != nil {
		t.ClaimsData = c.ClaimsData
	}
	if tag != nil {
		t.Add(tag...)
	}
	t.Add(Tag{"exp", fmt.Sprintf("%d", c.Expires)})
	t.Add(Tag{"iat", fmt.Sprintf("%d", c.IssuedAt)})
	t.Add(Tag{"nbf", fmt.Sprintf("%d", c.NotBefore)})
	t.Add(Tag{"type", string(c.Type)})
	t.Add(Tag{"jti", c.ID})
	t.Add(Tag{"name", c.Name})
	t.Add(Tag{"sub", c.Subject})
	t.Add(Tag{"iss", c.Issuer})

	fp := path.Join(Tokens, c.ID)
	if err := s.WriteEntry(fp, t); err != nil {
		return err
	}

	return s.Index.Index(c.ID, t.Tags...)
}

func (s *Store) ReadToken(id string) (*Token, error) {
	var t Token
	if err := s.ReadEntry(path.Join(Tokens, id), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

type Token struct {
	jwt.ClaimsData
	Tags []Tag  `json:"tags"`
	Data string `json:"data"`
}

func (t *Token) Add(tag ...Tag) {
	t.Tags = append(t.Tags, tag...)
}
