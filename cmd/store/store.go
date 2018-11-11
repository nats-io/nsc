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
	"path/filepath"
	"strings"
	"sync"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

const Version = "1"
const NSCFile = ".nsc"

const Users = "users"
const Accounts = "accounts"
const Clusters = "clusters"
const Servers = "servers"

var standardDirs = []string{Accounts, filepath.Join(Accounts, Users)}

// Store is a directory that contains nsc assets
type Store struct {
	sync.Mutex
	Dir string
}

func SafeName(n string) string {
	n = strings.TrimSpace(n)
	return n
}

// CreateStore creates a new Store in the specified directory.
// CreateStore will create the necessary directories and store the public key.
func CreateStore(dir string, name string, kp nkeys.KeyPair) (*Store, error) {
	var err error

	s := &Store{
		Dir: dir,
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	if len(files) != 0 {
		return nil, fmt.Errorf("%s is not empty, only an empty folder can be used for a new store", dir)
	}

	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("error reading public key: %v", err)
	}

	var v = jwt.NewGenericClaims(string(pub))
	v.Name = name
	if nkeys.IsValidPublicOperatorKey(pub) {
		v.Type = jwt.OperatorClaim
	} else {
		return nil, fmt.Errorf("unexpected key type %q", pub)
	}

	if err := ioutil.WriteFile(filepath.Join(s.Dir, ".nsc"), []byte(Version), 0600); err != nil {
		return nil, err
	}

	token, err := v.Encode(kp)
	if err != nil {
		return nil, err
	}

	fn := fmt.Sprintf("%s.jwt", SafeName(name))

	if err := ioutil.WriteFile(filepath.Join(s.Dir, fn), []byte(token), 0600); err != nil {
		return nil, err
	}

	t := Type{Version: Version, Kind: string(v.Type), Name: v.Name}

	if err := ioutil.WriteFile(filepath.Join(s.Dir, ".nsc"), []byte(t.String()), 0600); err != nil {
		return nil, err
	}

	for _, d := range standardDirs {
		dp := s.resolve(d, "")
		if err = os.MkdirAll(dp, 0700); err != nil {
			return nil, fmt.Errorf("error creating %q: %v", dp, err)
		}
	}

	return s, nil
}

type Type struct {
	Version string `json:"version"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
}

func (t *Type) String() string {
	d, err := json.Marshal(t)
	if err != nil {
		return fmt.Sprintf("error serializing store type: %v", err)
	}
	return string(d)
}

// LoadStore loads a store from the specified directory path.
func LoadStore(dir string) (*Store, error) {
	sf := filepath.Join(dir, NSCFile)
	if _, err := os.Stat(sf); os.IsNotExist(err) {
		return nil, fmt.Errorf("%q is not a valid configuration directory", sf)
	}
	s := &Store{
		Dir: dir,
	}
	return s, nil
}

func (s *Store) resolve(name ...string) string {
	return filepath.Join(s.Dir, filepath.Join(name...))
}

// Has returns true if the specified asset exists
func (s *Store) Has(name ...string) bool {
	fp := s.resolve(name...)
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
	return ioutil.ReadFile(fp)
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
