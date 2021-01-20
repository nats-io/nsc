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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwtv1 "github.com/nats-io/jwt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_AddOperator(t *testing.T) {
	ts := NewEmptyStore(t)

	_, err := os.Lstat(filepath.Join(ts.Dir, "store"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--name", "O", "--sys")
	require.NoError(t, err)

	require.FileExists(t, filepath.Join(ts.Dir, "store", "O", ".nsc"))
	require.FileExists(t, filepath.Join(ts.Dir, "store", "O", "O.jwt"))

	require.FileExists(t, filepath.Join(ts.Dir, "store", "O", "accounts", "SYS", "SYS.jwt"))
	require.FileExists(t, filepath.Join(ts.Dir, "store", "O", "accounts", "SYS", "users", "sys.jwt"))
}

func TestImportOperator(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	_, pub, kp := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pub)
	oc.Name = "O"
	token, err := oc.Encode(kp)
	require.NoError(t, err)
	tf := filepath.Join(ts.Dir, "O.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf)
	require.NoError(t, err)
	storeFile := filepath.Join(ts.Dir, "store", "O", ".nsc")
	require.FileExists(t, storeFile)

	check := func() {
		d, err := Read(storeFile)
		require.NoError(t, err)
		var info store.Info
		json.Unmarshal(d, &info)
		require.True(t, info.Managed)
		require.Equal(t, "O", info.Name)

		target := filepath.Join(ts.Dir, "store", "O", "O.jwt")
		require.FileExists(t, target)
		d, err = Read(target)
		require.NoError(t, err)
		require.Equal(t, token, string(d))
	}
	check()

	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf)
	require.Error(t, err)

	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf, "--force")
	require.NoError(t, err)
	check()

}

func TestAddOperatorInteractive(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	_, _, err := ExecuteInteractiveCmd(createAddOperatorCmd(), []interface{}{false, "O", "2019-12-01", "2029-12-01", true, true})
	require.NoError(t, err)
	d, err := Read(filepath.Join(ts.Dir, "store", "O", "O.jwt"))
	require.NoError(t, err)
	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)
	require.Equal(t, oc.Name, "O")
	start := time.Unix(oc.NotBefore, 0).UTC()
	require.Equal(t, 2019, start.Year())
	require.Equal(t, time.Month(12), start.Month())
	require.Equal(t, 1, start.Day())

	expiry := time.Unix(oc.Expires, 0).UTC()
	require.Equal(t, 2029, expiry.Year())
	require.Equal(t, time.Month(12), expiry.Month())
	require.Equal(t, 1, expiry.Day())
	require.NotEmpty(t, oc.SystemAccount)

	require.FileExists(t, filepath.Join(ts.Dir, "store", "O", "accounts", "SYS", "SYS.jwt"))
	require.FileExists(t, filepath.Join(ts.Dir, "store", "O", "accounts", "SYS", "users", "sys.jwt"))
}

func TestImportOperatorInteractive(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	_, pub, kp := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pub)
	oc.Name = "O"
	token, err := oc.Encode(kp)
	require.NoError(t, err)
	tf := filepath.Join(ts.Dir, "O.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)

	_, _, err = ExecuteInteractiveCmd(createAddOperatorCmd(), []interface{}{true, tf})
	require.NoError(t, err)

	target := filepath.Join(ts.Dir, "store", "O", "O.jwt")
	require.FileExists(t, target)
}

func Test_ImportOperatorFromURL(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	_, pub, kp := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pub)
	oc.Name = "O"
	token, err := oc.Encode(kp)
	require.NoError(t, err)

	// create an http server to accept the request
	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(token))
		require.NoError(t, err)
	}))
	defer hts.Close()

	u, err := url.Parse(hts.URL)
	require.NoError(t, err)
	u.Path = fmt.Sprintf("/jwt/v1/operators/%s", pub)
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", u.String())
	require.NoError(t, err)

	ts.SwitchOperator(t, "O")
	oo, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, pub, oo.Subject)
	require.True(t, ts.Store.IsManaged())
}

func Test_AddOperatorWithKey(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	seed, pub, _ := CreateOperatorKey(t)
	cmd := createAddOperatorCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteCmd(cmd, "--name", "T", "-K", string(seed))
	require.NoError(t, err)

	ts.SwitchOperator(t, "T")
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, pub, oc.Subject)
	require.Equal(t, pub, oc.Issuer)
}

func Test_AddOperatorWithKeyInteractive(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	seed, pub, _ := CreateOperatorKey(t)
	cmd := createAddOperatorCmd()
	HoistRootFlags(cmd)

	args := []interface{}{false, "T", "0", "0", false, false, string(seed)}
	_, _, err := ExecuteInteractiveCmd(cmd, args)
	require.NoError(t, err)

	ts.SwitchOperator(t, "T")
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, pub, oc.Subject)
}

func Test_AddWellKnownOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// create the managed operator store
	_, opk, okp := CreateOperatorKey(t)
	as, _ := RunTestAccountServerWithOperatorKP(t, okp)
	defer as.Close()

	// add an entry to well known
	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	var twko KnownOperator
	twko.AccountServerURL = ourl.String()
	twko.Name = "T"

	ops, _ := GetWellKnownOperators()
	ops = append(ops, twko)
	wellKnownOperators = ops

	// add the well known operator
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", "T")
	require.NoError(t, err)

	ts.SwitchOperator(t, "T")
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, opk, oc.Subject)
}

func Test_AddNotWellKnownOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// add the well known operator
	_, _, err := ExecuteCmd(createAddOperatorCmd(), "--url", "X")
	require.Error(t, err)
}

func Test_AddOperatorNameArg(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(HoistRootFlags(createAddOperatorCmd()), "X")
	require.NoError(t, err)
	ts.SwitchOperator(t, "X")

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, "X", oc.Name)
}

func TestImportOperatorV2(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	_, pub, kp := CreateOperatorKey(t)
	oc := jwtv1.NewOperatorClaims(pub)
	oc.Name = "O"
	token, err := oc.Encode(kp)
	require.NoError(t, err)
	tf := filepath.Join(ts.Dir, "O.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)

	_, stdErr, err := ExecuteCmd(createAddOperatorCmd(), "--url", tf)
	require.Error(t, err)
	require.Contains(t, stdErr, JWTUpgradeBannerJWT(1).Error())
}

func TestImportReIssuedOperator(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	checkOp := func(pub string) {
		s, err := GetStoreForOperator("O")
		require.NoError(t, err)
		claim, err := s.ReadOperatorClaim()
		require.NoError(t, err)
		require.Equal(t, claim.Subject, pub)
	}

	_, pubOld, kpOld := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pubOld)
	oc.Name = "O"
	token, err := oc.Encode(kpOld)
	require.NoError(t, err)
	tf := filepath.Join(ts.Dir, "Oold.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf)
	require.NoError(t, err)
	checkOp(pubOld)

	// simulate reissuing operator
	_, pubNew, kpNew := CreateOperatorKey(t)
	oc.Subject = pubNew
	token, err = oc.Encode(kpNew)
	require.NoError(t, err)
	tf = filepath.Join(ts.Dir, "Onew.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf, "--force")
	require.NoError(t, err)
	checkOp(pubNew)
}
