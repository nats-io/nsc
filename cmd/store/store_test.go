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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func MakeTempDir(t *testing.T) string {
	p, err := ioutil.TempDir("", "store_test")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func CreateUser(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(nkeys.CreateUser, t)
}

func CreateAccount(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(nkeys.CreateAccount, t)
}

func CreateOperator(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(nkeys.CreateOperator, t)
}

type NKeyFactory func() (nkeys.KeyPair, error)

func CreateNkey(f NKeyFactory, t *testing.T) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, string(pub), kp
}

func InitStore(t *testing.T) *Store {
	fp, err := ioutil.TempDir("", "store")
	if err != nil {
		t.Fatal("error creating temp dir", fp, err)
	}
	_, pub, _ := CreateAccount(t)
	s, err := CreateStore(fp, pub, "account", "test")
	require.NoError(t, err)

	_, _, okp := CreateOperator(t)

	ac := jwt.NewActivationClaims(pub)
	token, err := ac.Encode(okp)
	require.NoError(t, err)

	s.SetAccountActivation(token)
	return s
}

func TestFindStore(t *testing.T) {
	s := InitStore(t)
	sub := filepath.Join(s.Dir, "foo")
	err := os.Mkdir(sub, 0777)
	require.NoError(t, err)
	sub2 := filepath.Join(sub, "bar")
	err = os.Mkdir(sub2, 0777)
	require.NoError(t, err)

	sf, err := FindStoreDir(sub2)
	require.Equal(t, sf, s.Dir)
}

func TestDoNotFindStore(t *testing.T) {
	d := MakeTempDir(t)
	sub := filepath.Join(d, "foo")
	err := os.Mkdir(sub, 0777)
	require.NoError(t, err)
	sub2 := filepath.Join(sub, "bar")
	err = os.Mkdir(sub2, 0777)
	require.NoError(t, err)

	sf, err := FindStoreDir(sub2)
	require.Error(t, err)
	require.Equal(t, sf, "")
}

func TestLoadStoreRequiresKeyfile(t *testing.T) {
	d := MakeTempDir(t)
	s, err := LoadStore(d)
	require.Nil(t, s)
	require.True(t, os.IsNotExist(err))
	require.True(t, strings.Contains(err.Error(), NSCFile))
}

func TestDefaultStore(t *testing.T) {
	dir := MakeTempDir(t)
	_, pk, _ := CreateAccount(t)

	s, err := CreateStore(dir, pk, "account", "test")
	require.NoError(t, err)

	pk2, err := s.GetPublicKey()
	require.NoError(t, err)

	require.Equal(t, pk, pk2)
	require.Equal(t, dir, s.Dir)
}

func TestLoadStore(t *testing.T) {
	s := InitStore(t)
	dir := s.Dir
	s, err := LoadStore(dir)
	require.NoError(t, err)
	require.NotNil(t, s)

	kp, err := s.GetKey()
	require.NoError(t, err)
	require.NotNil(t, kp)

	pk, err := s.GetPublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.True(t, nkeys.IsValidPublicAccountKey([]byte(pk)))

	str, err := s.GetAccountActivation()
	require.NoError(t, err)

	ac, err := jwt.DecodeActivationClaims(str)
	require.NoError(t, err)
	require.NotNil(t, ac)
}

func TestStoreCrud(t *testing.T) {
	s := InitStore(t)
	err := s.Write("testfile", []byte("hello"))
	require.NoError(t, err)

	fi, err := os.Stat(filepath.Join(s.Dir, "testfile"))
	require.NoError(t, err)
	require.NotNil(t, fi)

	require.True(t, s.Has("testfile"))
	d, err := s.Read("testfile")
	require.NoError(t, err)
	require.Equal(t, "hello", string(d))

	s.Delete("testfile")
	require.False(t, s.Has("testfile"))
}

func TestStoreEntryCrud(t *testing.T) {
	s := InitStore(t)

	type ts struct {
		Name string
	}

	e := ts{"test"}

	err := s.WriteEntry("a/b", e)
	require.NoError(t, err)

	fi, err := os.Stat(filepath.Join(s.Dir, "a/b"))
	require.NoError(t, err)
	require.NotNil(t, fi)

	require.True(t, s.Has("a/b"))
	var v ts
	err = s.ReadEntry("a/b", &v)
	require.NoError(t, err)
	require.Equal(t, e, v)

	err = s.Delete("a/b")
	require.NoError(t, err)

	require.False(t, s.Has("a/b"))
}

func TestList(t *testing.T) {
	s := InitStore(t)

	type ts struct {
		Name string
	}

	e := ts{"test"}

	err := s.WriteEntry("a/b", e)
	require.NoError(t, err)

	err = s.WriteEntry("a/b.test", e)
	require.NoError(t, err)

	fi, err := os.Stat(filepath.Join(s.Dir, "a/b"))
	require.NoError(t, err)
	require.NotNil(t, fi)

	fi, err = os.Stat(filepath.Join(s.Dir, "a/b.test"))
	require.NoError(t, err)
	require.NotNil(t, fi)

	fns, err := s.List("a", "")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"b", "b.test"}, fns)

	fns, err = s.List("a", "test")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"b.test"}, fns)
}

func TestListingNonExisting(t *testing.T) {
	s := InitStore(t)

	type ts struct {
		Name string
	}

	e := ts{"test"}

	err := s.WriteEntry("a/b", e)
	require.NoError(t, err)

	fns, err := s.List("c", "")
	require.NoError(t, err)
	require.Nil(t, fns)
}

func TestListSkipsNested(t *testing.T) {
	s := InitStore(t)

	type ts struct {
		Name string
	}

	err := s.Write("a/b/c", []byte("Hello"))
	require.NoError(t, err)

	fns, err := s.List("a", "")
	require.NoError(t, err)
	require.Empty(t, fns)
}
