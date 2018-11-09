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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

// the keyfile name
const NSCFile = ".nsc"
const DefaultProfile = "default"
const AccountActivation = "account_activation"
const Activations = "activations"
const Users = "users"
const Exports = "exports"
const Imports = "imports"
const Tokens = "tokens"

// Store is a directory that contains nsc assets
type Store struct {
	sync.Mutex
	Dir   string
	Index *Index
}

// FindCurrentStoreDir tries to find a store director
// starting with the current working dif
func FindCurrentStoreDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return FindStoreDir(wd)
}

// FindStore starts at the directory provided and tries to
// find a directory containing the public key. This function
// checks dir and then works its way up the folder path.
func FindStoreDir(dir string) (string, error) {
	var err error

	pkp := filepath.Join(dir, NSCFile)

	if _, err := os.Stat(pkp); os.IsNotExist(err) {
		parent := filepath.Dir(dir)

		if parent == dir {
			return "", fmt.Errorf("no store directory found")
		}

		return FindStoreDir(parent)
	}

	return dir, err
}

// CreateStore creates a new Store in the specified directory.
// CreateStore will create the necessary directories and store the public key.
func CreateStore(dir string, pk string, sType string, name string) (*Store, error) {
	var err error

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, err
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	if len(files) != 0 {
		return nil, fmt.Errorf("%s is not empty, only an empty folder can be sused for a new store", dir)
	}

	_, err = nkeys.FromPublicKey([]byte(pk))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	s := &Store{
		Dir: dir,
	}
	s.Index = NewIndex(s)

	m := make(map[string]string)
	m["public_key"] = pk
	m["type"] = sType
	m["name"] = name

	d, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("error serializing .nsc file: %v", err)
	}
	// end fixme

	if err := ioutil.WriteFile(filepath.Join(s.Dir, ".nsc"), d, 0600); err != nil {
		return nil, err
	}
	return s, nil
}

// LoadStore loads a store from the specified directory path.
func LoadStore(dir string) (*Store, error) {
	pkf := filepath.Join(dir, NSCFile)
	if _, err := os.Stat(pkf); os.IsNotExist(err) {
		return nil, err
	}

	s := &Store{
		Dir: dir,
	}
	s.Index = NewIndex(s)

	return s, nil
}

func (s *Store) Close() error {
	if s.Index != nil {
		return s.Index.Close()
	}
	return nil
}

func (s *Store) FilePath(name string) string {
	return filepath.Join(s.Dir, name)
}

// Write writes the specified file name or subpath in the store
func (s *Store) Write(name string, data []byte) error {
	s.Lock()
	defer s.Unlock()

	fp := filepath.Join(s.Dir, name)
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
	fp := filepath.Join(s.Dir, name)
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		return false
	}
	return true
}

// Read reads the specified file name or subpath from the store
func (s *Store) Read(name string) ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	fp := filepath.Join(s.Dir, name)
	return ioutil.ReadFile(fp)
}

// Read reads the specified file name or subpath from the store
func (s *Store) Delete(name string) error {
	s.Lock()
	defer s.Unlock()
	fp := filepath.Join(s.Dir, name)
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
	d, err := s.Read(NSCFile)
	if err != nil {
		return nil, err
	}

	m := make(map[string]string)
	err = json.Unmarshal(d, &m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing .nsc file: %v", err)
	}

	pk, err := nkeys.FromPublicKey([]byte(m["public_key"]))
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
	dir := filepath.Join(s.Dir, subDir)

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
