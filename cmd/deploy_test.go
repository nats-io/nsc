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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_DeployKnownOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := ac.Subject

	as, storage := RunTestAccountServer(t)
	defer as.Close()

	// create a store with the remote operator
	remote := storage["operator"]
	onk := &store.NamedKey{Name: "T"}
	ots, err := store.CreateStore("T", filepath.Join(ts.Dir, "store"), onk)
	require.NoError(t, err)
	require.NoError(t, ots.StoreClaim([]byte(remote)))
	opk, err := ots.GetRootPublicKey()

	_, _, err = ExecuteCmd(createDeployCmd(), "--operator", "T")
	require.NotNil(t, storage[apk])
	aac, err := jwt.DecodeAccountClaims(string(storage[apk]))
	require.NoError(t, err)
	require.Equal(t, apk, aac.Subject)
	require.Equal(t, opk, aac.Issuer)

	require.NoError(t, err)
}

func Test_DeployUnknownOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := ac.Subject

	as, storage := RunTestAccountServer(t)
	defer as.Close()

	ourl, err := url.Parse(as.URL)
	ourl.Path = "/jwt/v1/operator"

	_, _, err = ExecuteCmd(createDeployCmd(), "--url", ourl.String())
	require.NotNil(t, storage[apk])
	aac, err := jwt.DecodeAccountClaims(string(storage[apk]))
	require.NoError(t, err)
	require.Equal(t, apk, aac.Subject)

	s, err := store.LoadStore(filepath.Join(ts.Dir, "store", "T"))
	require.NoError(t, err)
	oc, err := s.LoadRootClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
}

func Test_DeployInteractiveKnown(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := ac.Subject

	as, storage := RunTestAccountServer(t)
	defer as.Close()

	ourl, err := url.Parse(as.URL)
	ourl.Path = "/jwt/v1/operator"

	_, _, err = ExecuteInteractiveCmd(createDeployCmd(), []interface{}{0, 0, ourl.String()})
	require.NotNil(t, storage[apk])
	aac, err := jwt.DecodeAccountClaims(string(storage[apk]))
	require.NoError(t, err)
	require.Equal(t, apk, aac.Subject)

	s, err := store.LoadStore(filepath.Join(ts.Dir, "store", "T"))
	require.NoError(t, err)
	oc, err := s.LoadRootClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)

	// this time we pick the remote operator
	_, _, err = ExecuteInteractiveCmd(createDeployCmd(), []interface{}{0, 0})
	require.NotNil(t, storage[apk])
}

func RunTestAccountServerWithOperatorKP(t *testing.T, okp nkeys.KeyPair) (*httptest.Server, map[string][]byte) {
	storage := make(map[string][]byte)
	opk, err := okp.PublicKey()
	require.NoError(t, err)

	tas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errHandler := func(w http.ResponseWriter, err error) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
		getHandler := func(w http.ResponseWriter, r *http.Request) {
			id := filepath.Base(r.RequestURI)
			data := storage[id]
			if data == nil {
				w.WriteHeader(http.StatusNotFound)
			}
			w.Header().Add("Content-Type", "application/jwt")
			w.WriteHeader(200)
			w.Write(data)
		}

		updateHandler := func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				errHandler(w, err)
				return
			}

			ac, err := jwt.DecodeAccountClaims(string(body))
			if err != nil {
				errHandler(w, err)
				return
			}

			ok := false
			if ac.Claims().IsSelfSigned() || ac.Issuer == opk {
				ok = true
			} else {
				ok = ac.SigningKeys.Contains(ac.Issuer)
			}

			if ok {
				ac.Limits.Conn = -1
				ac.Limits.Data = -1
				ac.Limits.Exports = -1
				ac.Limits.Imports = -1
				ac.Limits.LeafNodeConn = -1
				ac.Limits.Payload = -1
				ac.Limits.Subs = -1
				ac.Limits.WildcardExports = true

				token, err := ac.Encode(okp)
				if err != nil {
					errHandler(w, err)
					return
				}
				storage[ac.Subject] = []byte(token)

				w.WriteHeader(200)
			} else {
				errHandler(w, fmt.Errorf("account %q not self-signed nor by a signer - issuer %q", ac.Subject, ac.Issuer))
			}
		}

		switch r.Method {
		case http.MethodGet:
			getHandler(w, r)
		case http.MethodPost:
			updateHandler(w, r)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	oc := jwt.NewOperatorClaims(opk)
	oc.Name = "T"
	oc.Subject = opk
	u, err := url.Parse(tas.URL)
	require.NoError(t, err)
	u.Path = "jwt/v1"
	oc.AccountServerURL = u.String()
	token, err := oc.Encode(okp)
	require.NoError(t, err)
	storage["operator"] = []byte(token)

	return tas, storage
}

// Runs a TestAccountServer returning the server and the underlying storage
func RunTestAccountServer(t *testing.T) (*httptest.Server, map[string][]byte) {
	_, _, okp := CreateOperatorKey(t)
	return RunTestAccountServerWithOperatorKP(t, okp)
}
