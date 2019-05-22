/*
 * Copyright 2018-2019 The NATS Authors
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func setOperatorAccountServer(t *testing.T, ts *TestStore, hts *httptest.Server, sk nkeys.KeyPair) {
	u, err := url.Parse(hts.URL)
	require.NoError(t, err)
	u.Path = "/jwt/v1/accounts"
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oc.AccountServerURL = u.String()

	if sk == nil {
		sk = ts.OperatorKey
	}
	token, err := oc.Encode(sk)
	require.NoError(t, err)

	err = ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
}

func Test_SyncOK(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	// create an http server to accept the request
	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			require.NoError(t, err)
		}
		_, err = jwt.DecodeAccountClaims(string(body))
		require.NoError(t, err)

		err = ts.Store.StoreClaim(body)
		require.NoError(t, err)

		w.WriteHeader(200)
	}))
	defer hts.Close()
	setOperatorAccountServer(t, ts, hts, nil)

	// edit the jwt
	_, _, err := ExecuteCmd(createEditAccount(), "--tag", "A")
	require.NoError(t, err)

	// sync the store
	_, _, err = ExecuteCmd(createSyncCommand(), "--account", "A")
	require.NoError(t, err)

	// verify the tag was stored
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "a")
}

func Test_SyncNoURL(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	// create an http server to accept the request
	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			require.NoError(t, err)
		}
		_, err = jwt.DecodeAccountClaims(string(body))
		require.NoError(t, err)

		err = ts.Store.StoreClaim(body)
		require.NoError(t, err)

		w.WriteHeader(200)
	}))
	defer hts.Close()

	// sync the store
	_, _, err := ExecuteCmd(createSyncCommand(), "--account", "A")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no account server url was provided")
}

func Test_SyncNoServer(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	// create an http server to accept the request
	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			require.NoError(t, err)
		}
		_, err = jwt.DecodeAccountClaims(string(body))
		require.NoError(t, err)

		err = ts.Store.StoreClaim(body)
		require.NoError(t, err)

		w.WriteHeader(200)
	}))
	setOperatorAccountServer(t, ts, hts, nil)
	hts.Close()

	// sync the store
	_, _, err := ExecuteCmd(createSyncCommand(), "--account", "A")
	require.Error(t, err)
	require.Contains(t, err.Error(), "connect: connection refused")
}

func Test_SyncManaged(t *testing.T) {
	_, pk, kp := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pk)
	oc.Name = "O"
	d, err := oc.Encode(kp)
	require.NoError(t, err)

	ts := NewTestStoreWithOperatorJWT(t, d)
	defer ts.Done(t)

	// create an http server to accept the request
	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			require.NoError(t, err)
		}
		ac, err := jwt.DecodeAccountClaims(string(body))
		require.NoError(t, err)

		token, err := ac.Encode(kp)
		require.NoError(t, err)

		d := []byte(token)
		err = ts.Store.StoreClaim(d)
		require.NoError(t, err)

		w.Header().Add("Content-Type", "application/jwt")
		w.WriteHeader(200)
		w.Write(d)
	}))
	defer hts.Close()

	// set the account server
	setOperatorAccountServer(t, ts, hts, kp)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, ac.IsSelfSigned())

	// sync the store
	_, _, err = ExecuteCmd(createSyncCommand(), "--account", "A")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.False(t, ac.IsSelfSigned())
	require.Equal(t, ac.Issuer, pk)
}
