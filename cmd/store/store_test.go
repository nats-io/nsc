// Copyright 2018-2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func MakeTempStore(t *testing.T, name string, kp nkeys.KeyPair) *Store {
	p := MakeTempDir(t)

	var nk *NamedKey
	if kp != nil {
		nk = &NamedKey{Name: name, KP: kp}
	}

	s, err := CreateStore(name, p, nk)
	require.NoError(t, err)
	require.NotNil(t, s)
	return s
}

func MakeTempDir(t *testing.T) string {
	p, err := os.MkdirTemp("", "store_test")
	require.NoError(t, err)
	return p
}

func CreateTestStoreForOperator(t *testing.T, name string, operator nkeys.KeyPair) *Store {
	s := MakeTempStore(t, name, operator)

	require.NotNil(t, s)
	require.FileExists(t, filepath.Join(s.Dir, ".nsc"))
	require.True(t, s.Has("", ".nsc"))

	if operator != nil {
		tokenName := fmt.Sprintf("%s.jwt", SafeName(name))
		require.FileExists(t, filepath.Join(s.Dir, tokenName))
		require.True(t, s.Has("", tokenName))
	}

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
	require.NoError(t, os.WriteFile(fp, []byte("hello"), 0666))

	_, _, kp := CreateAccountKey(t)
	_, err := CreateStore("foo", p, &NamedKey{Name: "foo", KP: kp})
	require.Error(t, err)
}

func TestUnsupportedKeyType(t *testing.T) {
	p := MakeTempDir(t)
	fp := filepath.Join(p, "test")
	require.NoError(t, os.WriteFile(fp, []byte("hello"), 0666))

	kp, err := nkeys.CreateServer()
	require.NoError(t, err)

	_, err = CreateStore("foo", p, &NamedKey{Name: "foo", KP: kp})
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
	exp := time.Now().Unix() + 5
	require.Zero(t, c.Expires)

	c.Expires = exp
	token, err := c.Encode(kp)
	require.NoError(t, err)

	_, err = s.StoreClaim([]byte(token))
	require.NoError(t, err)
	c, err = s.LoadClaim("x.jwt")
	require.NoError(t, err)
	require.Equal(t, c.Expires, exp)
}

func TestStoreAccount(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, _ := CreateAccountKey(t)
	s := CreateTestStoreForOperator(t, "x", kp)

	c := jwt.NewAccountClaims(apub)
	c.Name = "foo"
	cd, err := c.Encode(kp)
	require.NoError(t, err)
	_, err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)

	gc, err := s.LoadClaim(Accounts, "foo", "foo.jwt")
	require.NoError(t, err)
	require.NotNil(t, gc)
	require.Equal(t, gc.Name, "foo")
}

func TestStoreAccountWithSigningKey(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, _ := CreateAccountKey(t)
	s := CreateTestStoreForOperator(t, "x", kp)
	oc, err := s.ReadOperatorClaim()
	require.NoError(t, err)

	_, spk1, skp1 := CreateOperatorKey(t)
	_, spk2, _ := CreateOperatorKey(t)
	oc.SigningKeys.Add(spk1, spk2)
	cd, err := oc.Encode(kp)
	require.NoError(t, err)
	_, err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)

	oc, err = s.ReadOperatorClaim()
	require.NoError(t, err)
	require.Contains(t, oc.SigningKeys, spk1)
	require.Contains(t, oc.SigningKeys, spk2)

	c := jwt.NewAccountClaims(apub)
	c.Name = "foo"
	cd, err = c.Encode(skp1)
	require.NoError(t, err)
	_, err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)

	gc, err := s.LoadClaim(Accounts, "foo", "foo.jwt")
	require.NoError(t, err)
	require.NotNil(t, gc)
	require.Equal(t, gc.Name, "foo")
	require.True(t, oc.DidSign(gc))
}

func TestStoreUser(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, akp := CreateAccountKey(t)
	_, upub, _ := CreateUserKey(t)

	s := CreateTestStoreForOperator(t, "x", kp)

	ac := jwt.NewAccountClaims(apub)
	ac.Name = "foo"
	cd, err := ac.Encode(kp)
	require.NoError(t, err)
	_, err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)

	uc := jwt.NewUserClaims(upub)
	uc.Name = "bar"
	ud, err := uc.Encode(akp)
	require.NoError(t, err)

	_, err = s.StoreClaim([]byte(ud))
	require.NoError(t, err)

	gc, err := s.LoadClaim(Accounts, "foo", Users, "bar.jwt")
	require.NoError(t, err)
	require.NotNil(t, gc)
	require.Equal(t, gc.Name, "bar")
}

func TestStoreUserWithSigningKeys(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, _ := CreateAccountKey(t)
	_, spub, sakp := CreateAccountKey(t)
	_, upub, _ := CreateUserKey(t)

	s := CreateTestStoreForOperator(t, "x", kp)

	ac := jwt.NewAccountClaims(apub)
	ac.Name = "foo"
	ac.SigningKeys.Add(spub)
	cd, err := ac.Encode(kp)
	require.NoError(t, err)
	_, err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)

	uc := jwt.NewUserClaims(upub)
	uc.Name = "bar"
	uc.IssuerAccount = apub
	ud, err := uc.Encode(sakp)
	require.NoError(t, err)
	_, err = s.StoreClaim([]byte(ud))
	require.NoError(t, err)

	gc, err := s.LoadClaim(Accounts, "foo", Users, "bar.jwt")
	require.NoError(t, err)
	require.NotNil(t, gc)
	require.Equal(t, gc.Name, "bar")
	require.True(t, ac.DidSign(uc))
}

func TestStore_ListSubContainers(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, akp := CreateAccountKey(t)
	_, upub, _ := CreateUserKey(t)

	s := CreateTestStoreForOperator(t, "store", kp)

	ac := jwt.NewAccountClaims(apub)
	ac.Name = "foo"
	cd, err := ac.Encode(kp)
	require.NoError(t, err)
	rs, err := s.StoreClaim([]byte(cd))
	require.NoError(t, err)
	require.Nil(t, rs)

	uc := jwt.NewUserClaims(upub)
	uc.Name = "bar"
	ud, err := uc.Encode(akp)
	require.NoError(t, err)

	_, err = s.StoreClaim([]byte(ud))
	require.NoError(t, err)

	v, err := s.ListEntries(Accounts, "foo", Users)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, v, 1)
	require.Equal(t, "bar", v[0])
}

func TestStore_GetAccountKeys(t *testing.T) {
	_, _, kp := CreateOperatorKey(t)
	_, apub, _ := CreateAccountKey(t)

	s := CreateTestStoreForOperator(t, "O", kp)

	ctx, err := s.GetContext()
	require.NoError(t, err)

	keys, err := ctx.GetAccountKeys("A")
	require.NoError(t, err)
	require.Nil(t, keys)

	ac := jwt.NewAccountClaims(apub)
	ac.Name = "A"
	cd, err := ac.Encode(kp)
	require.NoError(t, err)
	rs, err := s.StoreClaim([]byte(cd))
	require.NoError(t, err)
	require.Nil(t, rs)

	keys, err = ctx.GetAccountKeys("A")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Contains(t, keys, apub)

	_, apub2, _ := CreateAccountKey(t)
	ac.SigningKeys.Add(apub2)
	cd, err = ac.Encode(kp)
	require.NoError(t, err)
	rs, err = s.StoreClaim([]byte(cd))
	require.NoError(t, err)
	require.Nil(t, rs)

	keys, err = ctx.GetAccountKeys("A")
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Equal(t, apub, keys[0])
	require.Equal(t, apub2, keys[1])
}

func assertErrorMessage(t *testing.T, err error, errMsg string) {
	require.Error(t, err)
	if errMsg != "" {
		require.Equal(t, errMsg, err.Error())
	}
}

func assertError(t *testing.T, v interface{}, err error, errMsg string) {
	require.Nil(t, v)
	assertErrorMessage(t, err, errMsg)
}

func TestStore_NilStore(t *testing.T) {
	var s *Store
	require.Empty(t, s.Resolve("A"))
	require.False(t, s.IsManaged())
	require.False(t, s.Has("foo"))
	require.False(t, s.HasAccount("foo"))
	require.Equal(t, "", s.GetName())
	assertErrorMessage(t, s.Write(nil, "hello"), NoStoreSetError)
	assertErrorMessage(t, s.StoreRaw(nil), NoStoreSetError)
	assertErrorMessage(t, s.Delete("foo"), NoStoreSetError)

	list, err := s.List(Accounts)
	assertError(t, list, err, NoStoreSetError)

	r, err := s.StoreClaim(nil)
	assertError(t, r, err, NoStoreSetError)

	k, err := s.GetRootPublicKey()
	require.Empty(t, k)
	assertErrorMessage(t, err, NoStoreSetError)

	e, err := s.ListEntries("foo")
	assertError(t, e, err, NoStoreSetError)

	sub, err := s.ListSubContainers("A")
	assertError(t, sub, err, NoStoreSetError)

	cd, err := s.LoadClaim("A")
	assertError(t, cd, err, NoStoreSetError)

	gc, err := s.LoadDefaultEntity(Accounts)
	assertError(t, gc, err, NoStoreSetError)

	gc, err = s.LoadRootClaim()
	assertError(t, gc, err, NoStoreSetError)

	ra, err := s.Read("A")
	assertError(t, ra, err, NoStoreSetError)

	ac, err := s.ReadAccountClaim("A")
	assertError(t, ac, err, NoStoreSetError)

	d, err := s.ReadRawAccountClaim("A")
	assertError(t, d, err, NoStoreSetError)

	oc, err := s.ReadOperatorClaim()
	assertError(t, oc, err, NoStoreSetError)

	d, err = s.ReadRawOperatorClaim()
	assertError(t, d, err, NoStoreSetError)

	uc, err := s.ReadUserClaim("A", "U")
	assertError(t, uc, err, NoStoreSetError)

	d, err = s.ReadRawUserClaim("A", "U")
	assertError(t, d, err, NoStoreSetError)
}
