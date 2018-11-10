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
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func MakeTempStore(t *testing.T, name string, kp nkeys.KeyPair) *Store {
	p := MakeTempDir(t)
	s, err := CreateStore(p, name, kp)
	require.NoError(t, err)
	require.NotNil(t, s)
	return s
}

func MakeTempDir(t *testing.T) string {
	p, err := ioutil.TempDir("", "store_test")
	require.NoError(t, err)
	return p
}

func CreateTestStore(t *testing.T, name string, storeType nkeys.PrefixByte) *Store {
	var kp nkeys.KeyPair
	var dirs []string
	switch storeType {
	case nkeys.PrefixByteAccount:
		_, _, kp = CreateAccountKey(t)
		dirs = accountDirs
	case nkeys.PrefixByteOperator:
		_, _, kp = CreateOperatorKey(t)
		dirs = operatorDirs
	case nkeys.PrefixByteCluster:
		_, _, kp = CreateClusterKey(t)
		dirs = clusterDirs
	}
	s := MakeTempStore(t, name, kp)

	require.NotNil(t, s)
	require.FileExists(t, filepath.Join(s.Dir, ".nsc"))
	require.True(t, s.Has("", ".nsc"))

	tokenName := fmt.Sprintf("%s.jwt", SafeName(name))
	require.FileExists(t, filepath.Join(s.Dir, tokenName))
	require.True(t, s.Has("", tokenName))

	for _, d := range dirs {
		require.DirExists(t, filepath.Join(s.Dir, d))
		require.True(t, s.Has(d, ""))
	}
	return s
}

func TestCreateStoreFailsOnNonEmptyDir(t *testing.T) {
	p := MakeTempDir(t)
	fp := filepath.Join(p, "test")
	require.NoError(t, ioutil.WriteFile(fp, []byte("hello"), 0666))

	_, _, kp := CreateAccountKey(t)
	_, err := CreateStore(p, "foo", kp)
	require.Error(t, err)
}

func TestUnsupportedKeyType(t *testing.T) {
	p := MakeTempDir(t)
	fp := filepath.Join(p, "test")
	require.NoError(t, ioutil.WriteFile(fp, []byte("hello"), 0666))

	kp, err := nkeys.CreateServer()
	require.NoError(t, err)

	_, err = CreateStore(p, "foo", kp)
	require.Error(t, err)
}

func TestAccountLoadStore(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteAccount)
	ss, err := LoadStore(s.Dir)
	require.NoError(t, err)
	require.NotNil(t, ss)
	require.Equal(t, s.Dir, ss.Dir)
}

func TestOperatorLoadStore(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteOperator)
	ss, err := LoadStore(s.Dir)
	require.NoError(t, err)
	require.NotNil(t, ss)
	require.Equal(t, s.Dir, ss.Dir)
}

func TestClusterLoadStore(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteCluster)
	ss, err := LoadStore(s.Dir)
	require.NoError(t, err)
	require.NotNil(t, ss)
	require.Equal(t, s.Dir, ss.Dir)
}

func TestCreateAccountStore(t *testing.T) {
	CreateTestStore(t, "test-account", nkeys.PrefixByteAccount)
}

func TestCreateOperatorStore(t *testing.T) {
	CreateTestStore(t, "test-operator", nkeys.PrefixByteOperator)
}

func TestCreateClusterStore(t *testing.T) {
	CreateTestStore(t, "test-cluster", nkeys.PrefixByteCluster)
}

func TestWriteFile(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteAccount)
	err := s.Write(Users, "foo", []byte("foo"))
	require.NoError(t, err)

	fp := filepath.Join(s.Dir, Users, "foo")
	require.FileExists(t, fp)
}

func TestReadFile(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteAccount)
	err := s.Write(Users, "foo", []byte("foo"))
	require.NoError(t, err)

	fp := filepath.Join(s.Dir, Users, "foo")
	require.FileExists(t, fp)

	d, err := s.Read(Users, "foo")
	require.NoError(t, err)
	require.Equal(t, "foo", string(d))
}

func TestListFiles(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteAccount)
	err := s.Write(Users, "foo", []byte("foo"))
	require.NoError(t, err)

	err = s.Write(Users, "bar", []byte("bar"))
	require.NoError(t, err)

	names, err := s.List(Users, "")
	require.NoError(t, err)
	require.ElementsMatch(t, names, []string{"foo", "bar"})
}

func TestDeleteFile(t *testing.T) {
	s := CreateTestStore(t, "test-account", nkeys.PrefixByteAccount)
	err := s.Write(Users, "foo", []byte("foo"))
	require.NoError(t, err)

	fp := filepath.Join(s.Dir, Users, "foo")
	require.FileExists(t, fp)

	err = s.Delete(Users, "foo")
	require.NoError(t, err)
	require.False(t, s.Has(Users, "foo"))
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

type NKeyFactory func() (nkeys.KeyPair, error)

func CreateNkey(t *testing.T, f NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, string(pub), kp
}
