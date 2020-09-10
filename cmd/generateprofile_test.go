/*
 * Copyright 2018-2020 The NATS Authors
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
	"encoding/json"
	"fmt"
	"github.com/nats-io/jwt"
	"net/url"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ParseNscURLs(t *testing.T) {
	type test struct {
		u    string
		err  bool
		want *NscURL
	}

	tests := []test{
		{u: "nsc://", err: true, want: nil},
		{u: "http://one", err: true, want: nil},
		{u: "nsc://one", err: false, want: &NscURL{operator: "one"}},
		{u: "nsc://one one/two", err: false, want: &NscURL{operator: "one one", account: "two"}},
		{u: "nsc://one/two/three", err: false, want: &NscURL{operator: "one", account: "two", user: "three"}},
		{u: "nsc://one?hello&world", err: false, want: &NscURL{operator: "one", qs: "hello&world"}},
	}

	for _, tc := range tests {
		u, err := ParseNscURL(tc.u)
		if tc.err && err == nil {
			t.Fatalf("error parsing %q - expected error, but got none", tc.u)
		}
		if !tc.err && err != nil {
			t.Fatalf("error parsing %q - expected no error, but got %v", tc.u, err)
		}
		require.Equal(t, tc.want, u)
	}
}

func Test_ParseNscURLQuery(t *testing.T) {
	type test struct {
		u    string
		want map[Arg]string
	}

	tests := []test{
		{u: "nsc://one?seed&name&key", want: map[Arg]string{seed: "", name: "", key: ""}},
		{u: "nsc://one/two/three?store=/tmp/storedir&keystore=/tmp/key+dir",
			want: map[Arg]string{
				storeDir:    "/tmp/storedir",
				keystoreDir: "/tmp/key dir"}},
	}

	for _, tc := range tests {
		u, err := ParseNscURL(tc.u)
		if err != nil {
			t.Fatalf("failed parsing query %q: %v", tc.u, err)
		}
		q, err := u.query()
		require.NoError(t, err)
		require.Equal(t, tc.want, q)
	}
}

func Test_NscURLEncodedNames(t *testing.T) {
	t.Log(url.QueryEscape("My Company Inc."))
	nu, err := ParseNscURL("nsc://My+Company+Inc./Account+Name/")
	require.NoError(t, err)
	o, err := nu.getOperator()
	require.NoError(t, err)
	require.Equal(t, "My Company Inc.", o)

	a, err := nu.getAccount()
	require.NoError(t, err)
	require.Equal(t, "Account Name", a)

	u, err := nu.getUser()
	require.NoError(t, err)
	require.Equal(t, "", u)
}

func loadResults(t *testing.T, out string) Profile {
	d, err := Read(out)
	require.NoError(t, err)
	var r Profile
	require.NoError(t, json.Unmarshal(d, &r))
	return r
}

func Test_ProfileIDs(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	o := ts.GetOperatorPublicKey(t)
	a := ts.GetAccountPublicKey(t, "A")
	u := ts.GetUserPublicKey(t, "A", "U")

	out := path.Join(ts.Dir, "out.json")
	nu := fmt.Sprintf("nsc://%s/%s/%s?operatorName&accountName&userName", o, a, u)
	_, _, err := ExecuteCmd(createProfileCmd(), "-o", out, nu)
	require.NoError(t, err)

	r := loadResults(t, out)
	require.Equal(t, "O", r.Operator.Name)
	require.Equal(t, "A", r.Account.Name)
	require.Equal(t, "U", r.User.Name)
}

func Test_ProfileSeedIDs(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// add a signing key
	osk, opk, okp := CreateOperatorKey(t)
	ts.KeyStore.Store(okp)
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	kp, err := ts.KeyStore.GetKeyPair(oc.Issuer)
	require.NoError(t, err)
	require.NoError(t, err)
	oc.SigningKeys.Add(opk)
	sjwt, err := oc.Encode(kp)
	require.NoError(t, err)
	_, err = ts.Store.StoreClaim([]byte(sjwt))
	require.NoError(t, err)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	o := ts.GetOperatorPublicKey(t)
	a := ts.GetAccountPublicKey(t, "A")
	u := ts.GetUserPublicKey(t, "A", "U")

	out := path.Join(ts.Dir, "out.json")
	nu := fmt.Sprintf("nsc://%s/%s/%s?operatorSeed=%s", o, a, u, opk)
	_, _, err = ExecuteCmd(createProfileCmd(), "-o", out, nu)
	require.NoError(t, err)

	r := loadResults(t, out)
	require.Equal(t, string(osk), r.Operator.Seed)
}

func Test_ProfileStoreAndKeysDir(t *testing.T) {
	// create store
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	opk := ts.GetOperatorPublicKey(t)
	apk := ts.GetAccountPublicKey(t, "A")
	upk := ts.GetUserPublicKey(t, "A", "U")

	// context for the store is replaced
	ts2 := NewTestStore(t, "OO")
	defer ts2.Done(t)
	ts2.AddAccount(t, "AA")
	ts2.AddUser(t, "AA", "UU")

	stdout, _, err := ExecuteCmd(rootCmd, "describe", "operator", "--raw")
	require.NoError(t, err)
	ojwt, err := jwt.DecodeOperatorClaims(stdout)
	require.NoError(t, err)
	require.Equal(t, "OO", ojwt.Name)

	out := path.Join(ts.Dir, "out.json")
	storeDir := path.Join(ts.Dir, "store")
	keyDir := path.Join(ts.Dir, "keys")
	u := fmt.Sprintf("nsc://O/A/U?operatorName&accountName&userName&operatorKey&accountKey&userKey&store=%s&keyStore=%s", storeDir, keyDir)

	_, _, err = ExecuteCmd(rootCmd, "generate", "profile", "-o", out, u)
	require.NoError(t, err)
	r := loadResults(t, out)

	require.Equal(t, "O", r.Operator.Name)
	require.Equal(t, opk, r.Operator.Key)
	require.Equal(t, "A", r.Account.Name)
	require.Equal(t, apk, r.Account.Key)
	require.Equal(t, "U", r.User.Name)
	require.Equal(t, upk, r.User.Key)
}

func TestKey_ProfileBasics(t *testing.T) {
	type test struct {
		u    string
		want []Arg
	}

	tests := []test{
		{u: "nsc://O?operatorSeed&operatorKey", want: []Arg{operatorKey, operatorSeed}},
		{u: "nsc://O?key&seed", want: []Arg{operatorKey, operatorSeed}},
		{u: "nsc://O/A?key&seed", want: []Arg{accountKey, accountSeed}},
		{u: "nsc://O/A/U?key&seed", want: []Arg{userKey, userSeed}},
	}

	for _, tc := range tests {
		// create an env matching the u
		u, err := ParseNscURL(tc.u)
		if err != nil {
			t.Fatalf("error parsing %q", tc.u)
		}
		ts := NewTestStore(t, u.operator)
		require.NoError(t, err)
		oseed, err := ts.OperatorKey.Seed()
		require.NoError(t, err)
		opub, err := ts.OperatorKey.PublicKey()
		require.NoError(t, err)

		var aseed []byte
		var apub string
		if u.account != "" {
			ts.AddAccount(t, u.account)
			akp := ts.GetAccountKey(t, u.account)
			aseed, err = akp.Seed()
			require.NoError(t, err)
			apub, err = akp.PublicKey()
			require.NoError(t, err)
		}
		var useed []byte
		var upub string
		if u.user != "" {
			ts.AddUser(t, u.account, u.user)
			ukp := ts.GetUserKey(t, u.account, u.user)
			useed, err = ukp.Seed()
			require.NoError(t, err)
			upub, err = ukp.PublicKey()
			require.NoError(t, err)
		}

		// execute the command
		out := path.Join(ts.Dir, "out.json")
		_, _, err = ExecuteCmd(createProfileCmd(), "-o", out, tc.u)
		require.NoError(t, err)
		r := loadResults(t, out)

		q, err := u.query()
		require.NoError(t, err)
		require.Equal(t, len(tc.want), len(q))
		// check ask keys
		for _, k := range tc.want {
			switch k {
			case operatorKey:
				require.Equal(t, opub, r.Operator.Key)
			case accountKey:
				require.Equal(t, apub, r.Account.Key)
			case userKey:
				require.Equal(t, upub, r.User.Key)
			case key:
				if u.user != "" {
					require.Equal(t, upub, r.User.Key)
				} else if u.account != "" {
					require.Equal(t, apub, r.Account.Key)
				} else {
					require.Equal(t, opub, r.Operator.Key)
				}
			case operatorSeed:
				require.Equal(t, string(oseed), r.Operator.Seed)
			case accountSeed:
				require.Equal(t, string(aseed), r.Account.Seed)
			case userSeed:
				require.Equal(t, string(useed), r.User.Seed)
			case seed:
				if u.user != "" {
					require.Equal(t, string(useed), r.User.Seed)
				} else if u.account != "" {
					require.Equal(t, string(aseed), r.Account.Seed)
				} else {
					require.Equal(t, string(oseed), r.Operator.Seed)
				}
			case storeDir:
			case keystoreDir:
			}
		}

		ts.Done(t)
	}
}
