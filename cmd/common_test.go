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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt"

	"github.com/spf13/cobra"

	"github.com/mitchellh/go-homedir"
	jwtv2 "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func TestCommon_ResolvePath(t *testing.T) {
	v := ResolvePath("bar", "foo")
	require.Equal(t, v, "bar", "non defined variable")

	v = ResolvePath("bar", "")
	require.Equal(t, v, "bar", "empty variable")

	os.Setenv("foo", "foobar")
	v = ResolvePath("bar", "foo")
	require.Equal(t, v, "foobar", "env set")
}

func TestCommon_GetOutput(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal("error creating tmpdir", err)
	}

	type testd struct {
		fp      string
		create  bool
		isError bool
		isDir   bool
	}
	tests := []testd{
		{"--", false, false, false},
		{filepath.Join(dir, "dir"), true, true, true},
		{filepath.Join(dir, "nonExisting"), false, false, false},
		{filepath.Join(dir, "existing"), false, false, false},
	}
	for _, d := range tests {
		if d.isDir {
			os.MkdirAll(d.fp, 0777)
		} else if d.create {
			os.Create(d.fp)
		}
		file, err := GetOutput(d.fp)
		if file != nil && d.fp != "--" {
			file.Close()
		}
		if d.isError && err == nil {
			t.Errorf("expected error creating %#q, but didn't", d.fp)
		}
		if !d.isError && err != nil {
			t.Errorf("unexpected error creating %#q: %v", d.fp, err)
		}
	}
}

func createWriteCmd(t *testing.T) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Write(out, []byte("hello"))
		},
	}
	cmd.Flags().StringVarP(&out, "out", "", "--", "")
	return cmd
}

func Test_WriteDestinations(t *testing.T) {
	stdout, _, err := ExecuteCmd(createWriteCmd(t), "--out", "--")
	require.NoError(t, err)
	require.Contains(t, stdout, "hello")
	dir := MakeTempDir(t)
	fn := filepath.Join(dir, "test.txt")
	_, _, err = ExecuteCmd(createWriteCmd(t), "--out", fn)
	require.NoError(t, err)
	require.FileExists(t, fn)
	d, err := ioutil.ReadFile(fn)
	require.NoError(t, err)
	require.Contains(t, string(d), "hello")
}

func TestCommon_IsStdOut(t *testing.T) {
	require.True(t, IsStdOut("--"))
	require.False(t, IsStdOut("/tmp/foo.txt"))
}

func TestCommon_ResolveKeyEmpty(t *testing.T) {
	old := KeyPathFlag
	KeyPathFlag = ""

	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)
	require.Nil(t, rkp)
}

func TestCommon_ResolveKeyFromSeed(t *testing.T) {
	seed, p, _ := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = string(seed)

	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)

	pp, err := rkp.PublicKey()
	require.NoError(t, err)

	require.Equal(t, pp, p)
}

func TestCommon_ResolveKeyFromFile(t *testing.T) {
	dir := MakeTempDir(t)
	_, p, kp := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = StoreKey(t, kp, dir)
	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)

	pp, err := rkp.PublicKey()
	require.NoError(t, err)

	require.Equal(t, pp, p)
}

func TestCommon_ParseNumber(t *testing.T) {
	type testd struct {
		input   string
		output  int64
		isError bool
	}
	tests := []testd{
		{"", 0, false},
		{"0", 0, false},
		{"1000", 1000, false},
		{"1K", 1000, false},
		{"1k", 1000, false},
		{"1M", 1000000, false},
		{"1m", 1000000, false},
		{"1G", 1000000000, false},
		{"1g", 1000000000, false},
		{"32a", 0, true},
	}
	for _, d := range tests {
		v, err := ParseNumber(d.input)
		if err != nil && !d.isError {
			t.Errorf("%s didn't expect error: %v", d.input, err)
			continue
		}
		if err == nil && d.isError {
			t.Errorf("expected error from %s", d.input)
			continue
		}
		if v != d.output {
			t.Errorf("%s expected %d but got %d", d.input, d.output, v)
		}
	}
}

func TestCommon_NKeyValidatorActualKey(t *testing.T) {
	as, _, _ := CreateAccountKey(t)
	fn := NKeyValidator(nkeys.PrefixByteAccount)
	require.NoError(t, fn(string(as)))

	os, _, _ := CreateOperatorKey(t)
	require.Error(t, fn(string(os)))
}

func TestCommon_NKeyValidatorKeyInFile(t *testing.T) {
	dir := MakeTempDir(t)
	as, _, _ := CreateAccountKey(t)
	os, _, _ := CreateOperatorKey(t)

	require.NoError(t, Write(filepath.Join(dir, "as.nk"), as))
	require.NoError(t, Write(filepath.Join(dir, "os.nk"), os))

	fn := NKeyValidator(nkeys.PrefixByteAccount)
	require.NoError(t, fn(filepath.Join(dir, "as.nk")))

	require.Error(t, fn(filepath.Join(dir, "os.nk")))
}

func TestCommon_LoadFromURL(t *testing.T) {
	v := "1,2,3"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, v)
	}))
	defer ts.Close()

	d, err := LoadFromURL(ts.URL)
	require.NoError(t, err)
	require.Equal(t, v, string(d))
}

func TestCommon_LoadFromURLTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second * 6)
	}))
	defer ts.Close()

	_, err := LoadFromURL(ts.URL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Timeout exceeded")
}

func TestCommon_IsValidDir(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, IsValidDir(d))

	tp := filepath.Join(d, "foo")
	err := IsValidDir(tp)
	require.Error(t, err)
	require.True(t, os.IsNotExist(err))

	err = ioutil.WriteFile(tp, []byte("hello"), 0600)
	require.NoError(t, err)
	err = IsValidDir(tp)
	require.Error(t, err)
	require.Equal(t, "not a directory", err.Error())
}

func TestCommon_MaybeMakeDir(t *testing.T) {
	d := MakeTempDir(t)
	dir := filepath.Join(d, "foo")
	_, err := os.Stat(dir)
	require.True(t, os.IsNotExist(err))
	err = MaybeMakeDir(dir)
	require.NoError(t, err)
	require.DirExists(t, dir)

	// test no fail if exists
	err = MaybeMakeDir(dir)
	require.NoError(t, err)
}

func TestCommon_MaybeMakeDir_FileExists(t *testing.T) {
	d := MakeTempDir(t)
	fp := filepath.Join(d, "foo")
	err := Write(fp, []byte("hello"))
	require.NoError(t, err)

	err = MaybeMakeDir(fp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is not a dir")
}

func TestCommon_Read(t *testing.T) {
	d := MakeTempDir(t)
	dir := filepath.Join(d, "foo", "bar", "baz")
	err := MaybeMakeDir(dir)
	require.NoError(t, err)

	fp := filepath.Join(dir, "..", "..", "foo.txt")
	err = Write(fp, []byte("hello"))
	require.NoError(t, err)

	require.DirExists(t, dir)
	require.FileExists(t, filepath.Join(d, "foo", "foo.txt"))
	data, err := Read(fp)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestCommon_WriteJSON(t *testing.T) {
	d := MakeTempDir(t)
	fp := filepath.Join(d, "foo")

	n := struct {
		Name string `json:"name"`
	}{}
	n.Name = "test"

	err := WriteJson(fp, n)
	require.NoError(t, err)

	v, err := Read(fp)
	require.NoError(t, err)
	require.JSONEq(t, `{"name": "test"}`, string(v))
}

func TestCommon_ReadJSON(t *testing.T) {
	d := MakeTempDir(t)
	fp := filepath.Join(d, "foo")
	err := Write(fp, []byte(`{"name": "test"}`))
	require.NoError(t, err)

	n := struct {
		Name string `json:"name"`
	}{}

	err = ReadJson(fp, &n)
	require.NoError(t, err)
	require.Equal(t, "test", n.Name)
}

func TestCommon_AbbrevHomePaths(t *testing.T) {
	require.Equal(t, "", AbbrevHomePaths(""))
	require.Equal(t, "/foo/bar", AbbrevHomePaths("/foo/bar"))
	v, err := homedir.Dir()
	if err != nil {
		require.Equal(t, "~/bar", AbbrevHomePaths(filepath.Join(v, "bar")))
	}
}

func Test_NKeyValidator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	os, opk, _ := CreateOperatorKey(t)
	as, pk, _ := CreateAccountKey(t)
	asf := filepath.Join(ts.Dir, "account_seed_file.nk")
	require.NoError(t, ioutil.WriteFile(asf, as, 0700))
	pkf := filepath.Join(ts.Dir, "account_public_file.nk")
	require.NoError(t, ioutil.WriteFile(pkf, []byte(pk), 0700))
	nff := filepath.Join(ts.Dir, "not_exist.nk")

	var keyTests = []struct {
		arg string
		ok  bool
	}{
		{asf, true},
		{pkf, true},
		{nff, false},
		{ts.Dir, false},
		{string(as), true},
		{string(as), true},
		{pk, true},
		{string(os), false},
		{opk, false},
		{"", false},
		{"foo", false},
	}

	fun := NKeyValidator(nkeys.PrefixByteAccount)
	for i, kt := range keyTests {
		err := fun(kt.arg)
		var failed bool
		message := fmt.Sprintf("unexpected error on test %q (%d): %v", kt.arg, i, err)
		if err != nil {
			failed = true
		}
		require.Equal(t, !kt.ok, failed, message)
	}
}

func Test_SeedNKeyValidatorMatching(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	os, opk, _ := CreateOperatorKey(t)
	as, pk, _ := CreateAccountKey(t)
	as1, pk1, _ := CreateAccountKey(t)
	as2, pk2, _ := CreateAccountKey(t)

	validPubs := []string{string(pk), string(pk1)}

	var keyTests = []struct {
		arg string
		ok  bool
	}{
		{string(os), false},
		{"", false},
		{"foo", false},
		{pk, false},
		{pk2, false},
		{opk, false},
		{filepath.Join(ts.Dir, "notexist.nk"), false},
		{string(as2), false},
		{string(as), true},
		{string(as1), true},
	}

	fun := SeedNKeyValidatorMatching(validPubs, nkeys.PrefixByteAccount)
	for i, kt := range keyTests {
		err := fun(kt.arg)
		var failed bool
		message := fmt.Sprintf("unexpected error on test %q (%d): %v", kt.arg, i, err)
		if err != nil {
			failed = true
		}
		require.Equal(t, !kt.ok, failed, message)
	}
}

func TestPushAccount(t *testing.T) {
	_, opk, okp := CreateOperatorKey(t)

	// create an http server to accept the request
	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			require.NoError(t, err)
		}
		ac, err := jwt.DecodeAccountClaims(string(body))
		require.NoError(t, err)

		token, err := ac.Encode(okp)
		require.NoError(t, err)

		w.Header().Add("Content-Type", "application/jwt")
		w.WriteHeader(200)
		w.Write([]byte(token))
	}))
	defer hts.Close()

	// self sign a jwt
	_, apk, akp := CreateAccountKey(t)
	ac := jwt.NewAccountClaims(apk)
	araw, err := ac.Encode(akp)
	require.NoError(t, err)

	u, err := url.Parse(hts.URL)
	require.NoError(t, err)
	_, sraw, err := PushAccount(u.String(), []byte(araw))
	require.NoError(t, err)
	require.NotNil(t, sraw)

	ac, err = jwt.DecodeAccountClaims(string(sraw))
	require.NoError(t, err)
	require.Equal(t, apk, ac.Subject)
	require.Equal(t, opk, ac.Issuer)
}

func Test_NameFlagArgOnlyOnEmpty(t *testing.T) {
	var tests = []struct {
		n   string
		a   []string
		out string
	}{
		{"", nil, ""},
		{"a", nil, "a"},
		{"a", []string{}, "a"},
		{"a", []string{"b", "c"}, "a"},
		{"", []string{"b", "c"}, "b"},
	}

	for i, v := range tests {
		r := nameFlagOrArgument(v.n, v.a)
		require.Equal(t, v.out, r, "failed test %d", i)
	}
}

func Test_OperatorV2(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	dir := filepath.Join(ts.Dir, "store", "O")
	tf := filepath.Join(dir, "O.jwt")
	oc := jwtv2.NewOperatorClaims(ts.GetOperatorPublicKey(t))
	oc.Name = "O"
	theJwt, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	err = ioutil.WriteFile(tf, []byte(theJwt), 0700)
	require.NoError(t, err)
	_, stdErr, err := ExecuteCmd(rootCmd, "env")
	require.Error(t, err)
	require.Contains(t, stdErr, JWTUpgradeBannerStore())
}
