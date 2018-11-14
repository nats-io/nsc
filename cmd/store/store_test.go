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

	"github.com/nats-io/jwt"

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

func CreateTestStoreForOperator(t *testing.T, name string, operator nkeys.KeyPair) *Store {
	s := MakeTempStore(t, name, operator)

	require.NotNil(t, s)
	require.FileExists(t, filepath.Join(s.Dir, ".nsc"))
	require.True(t, s.Has("", ".nsc"))

	tokenName := fmt.Sprintf("%s.jwt", SafeName(name))
	require.FileExists(t, filepath.Join(s.Dir, tokenName))
	require.True(t, s.Has("", tokenName))

	for _, d := range standardDirs {
		require.DirExists(t, filepath.Join(s.Dir, d))
		require.True(t, s.Has(d, ""))
	}
	return s
}

func CreateTestStore(t *testing.T, name string) *Store {
	var kp nkeys.KeyPair
	_, _, kp = CreateOperatorKey(t)
	return CreateTestStoreForOperator(t, name, kp)
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

func TestOperatorLoadStore(t *testing.T) {
	s := CreateTestStore(t, "test-account")
	ss, err := LoadStore(s.Dir)
	require.NoError(t, err)
	require.NotNil(t, ss)
	require.Equal(t, s.Dir, ss.Dir)
}

func TestCreateOperatorStore(t *testing.T) {
	CreateTestStore(t, "test-operator")
}

func TestWriteFile(t *testing.T) {
	s := CreateTestStore(t, "test-account")
	err := s.Write([]byte("foo"), Users, "foo")
	require.NoError(t, err)

	fp := filepath.Join(s.Dir, Users, "foo")
	require.FileExists(t, fp)
}

func TestReadFile(t *testing.T) {
	s := CreateTestStore(t, "test-account")
	err := s.Write([]byte("foo"), Users, "foo")
	require.NoError(t, err)

	fp := filepath.Join(s.Dir, Users, "foo")
	require.FileExists(t, fp)

	d, err := s.Read(Users, "foo")
	require.NoError(t, err)
	require.Equal(t, "foo", string(d))
}

func TestListFiles(t *testing.T) {
	s := CreateTestStore(t, "test-account")
	err := s.Write([]byte("foo"), Users, "foo")
	require.NoError(t, err)

	err = s.Write([]byte("bar"), Users, "bar")
	require.NoError(t, err)

	infos, err := s.List(Users, "")
	require.NoError(t, err)

	var names []string
	for _, i := range infos {
		names = append(names, i.Name())
	}
	require.ElementsMatch(t, names, []string{"foo", "bar"})
}

func TestDeleteFile(t *testing.T) {
	s := CreateTestStore(t, "test-account")
	err := s.Write([]byte("foo"), Users, "foo")
	require.NoError(t, err)

	fp := filepath.Join(s.Dir, Users, "foo")
	require.FileExists(t, fp)

	err = s.Delete(Users, "foo")
	require.NoError(t, err)
	require.False(t, s.Has(Users, "foo"))
}

func TestLoadOperator(t *testing.T) {
	s := CreateTestStore(t, "x")
	require.True(t, s.Has(JwtName("x")))
	c, err := s.LoadRootClaim()
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestStoreOperator(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	s := CreateTestStoreForOperator(t, "x", kp)
	c, err := s.LoadClaim("x.jwt")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Empty(t, c.Tags)

	c.Tags.Add("A", "B", "C")
	token, err := c.Encode(kp)
	require.NoError(t, err)

	err = s.StoreClaim([]byte(token))
	require.NoError(t, err)
	c, err = s.LoadClaim("x.jwt")
	require.NoError(t, err)
	require.Len(t, c.Tags, 3)
}

func TestStoreAccount(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, _ := CreateAccountKey(t)
	s := CreateTestStoreForOperator(t, "x", kp)

	c := jwt.NewAccountClaims(apub)
	c.Name = "foo"
	cd, err := c.Encode(kp)
	require.NoError(t, err)
	err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)

	gc, err := s.LoadClaim(Accounts, "foo", "foo.jwt")
	require.NoError(t, err)
	require.NotNil(t, gc)
	require.Equal(t, gc.Name, "foo")
}

func TestStoreUser(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, akp := CreateAccountKey(t)
	_, upub, _ := CreateUserKey(t)

	s := CreateTestStoreForOperator(t, "x", kp)

	ac := jwt.NewAccountClaims(apub)
	ac.Name = "foo"
	cd, err := ac.Encode(kp)
	err = s.StoreClaim([]byte(cd))

	uc := jwt.NewUserClaims(upub)
	uc.Name = "bar"
	ud, err := uc.Encode(akp)

	err = s.StoreClaim([]byte(ud))
	require.NoError(t, err)

	gc, err := s.LoadClaim(Accounts, "foo", Users, "bar.jwt")
	require.NoError(t, err)
	require.NotNil(t, gc)
	require.Equal(t, gc.Name, "bar")
}
