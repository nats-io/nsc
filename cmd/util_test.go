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
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func MakeTempStore(t *testing.T, name string, kp nkeys.KeyPair) *store.Store {
	p := MakeTempDir(t)
	s, err := store.CreateStore(p, name, kp)
	require.NoError(t, err)
	require.NotNil(t, s)
	return s
}

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

func CreateAccountKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateAccount)
}

func CreateOperatorKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateOperator)
}

func CreateNkey(t *testing.T, f NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, string(pub), kp
}
