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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

type TestStore struct {
	Dir      string
	StartDir string

	Store    *store.Store
	KeyStore store.KeyStore

	OperatorKey     nkeys.KeyPair
	OperatorKeyPath string

	AccountKey     nkeys.KeyPair
	AccountKeyPath string
}

func NewTestStore(t *testing.T, name string) *TestStore {
	var ts TestStore
	var err error

	// ngsStore is a global - so first test to get it initializes it
	ngsStore = nil

	_, _, ts.OperatorKey = CreateOperatorKey(t)
	_, _, ts.AccountKey = CreateAccountKey(t)

	ts.StartDir, err = os.Getwd()
	require.NoError(t, err)
	ts.Dir = MakeTempDir(t)

	storeDir := filepath.Join(ts.Dir, "store")
	err = os.Mkdir(storeDir, 0700)
	require.NoError(t, err, "error creating %q", storeDir)

	nkeysDir := filepath.Join(ts.Dir, "keys")
	err = os.Mkdir(nkeysDir, 0700)
	require.NoError(t, err, "error creating %q", nkeysDir)
	err = os.Setenv(store.NKeysPathEnv, nkeysDir)
	require.NoError(t, err, "nkeys env")

	ts.Store, err = store.CreateStore(name, storeDir, store.NamedKey{Name: "operator", KP: ts.OperatorKey})
	ctx, err := ts.Store.GetContext()
	require.NoError(t, err, "getting context")

	ts.KeyStore = ctx.KeyStore
	ts.OperatorKeyPath, err = ts.KeyStore.Store("operator", ts.OperatorKey, "")
	require.NoError(t, err, "store operator key")
	ts.AccountKeyPath, err = ts.KeyStore.Store(name, ts.AccountKey, "operator")
	require.NoError(t, err, "store account key")

	os.Chdir(ts.Store.Dir)

	return &ts
}

func (ts *TestStore) Done(t *testing.T) {
	if t.Failed() {
		t.Log("test artifacts:", ts.Dir)
	}
	os.Chdir(ts.StartDir)
}

//func MakeTempStore(t *testing.T, name string, kp nkeys.KeyPair) *store.Store {
//	p := MakeTempDir(t)
//	err := os.Setenv(store.NKeysPathEnv, filepath.Join(p, "nkeys"))
//	require.NoError(t, err, "setting environment")
//	kind, err := store.KeyType(kp)
//	require.NoError(t, err, "getting key kind")
//	keyName := fmt.Sprintf("%s_%s", name, store.KeyTypeLabel(kind))
//	s, err := store.CreateStore(name, p, store.NamedKey{Name: keyName, KP: kp})
//	require.NoError(t, err, "creating store")
//	require.NotNil(t, s, "store not nil")
//	return s
//}

func MakeTempDir(t *testing.T) string {
	p, err := ioutil.TempDir("", "store_test")
	require.NoError(t, err)
	return p
}

func StoreKey(t *testing.T, kp nkeys.KeyPair, dir string) string {
	p, err := kp.PublicKey()
	require.NoError(t, err)

	s, err := kp.Seed()
	require.NoError(t, err)

	fp := filepath.Join(dir, string(p)+".nk")
	err = ioutil.WriteFile(fp, s, 0600)
	require.NoError(t, err)
	return fp
}

func CreateClusterKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateCluster)
}

func CreateServerKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateServer)
}

func CreateAccountKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateAccount)
}

func CreateUserKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateUser)
}

func CreateOperatorKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateOperator)
}

func CreateNkey(t *testing.T, f store.NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, string(pub), kp
}
