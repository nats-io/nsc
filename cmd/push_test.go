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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SyncOK(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp)
	defer as.Close()

	ts := NewTestStoreWithOperator(t, "T", okp)
	err := ts.Store.StoreRaw(m["operator"])
	require.NoError(t, err)
	ts.AddAccount(t, "A")

	// edit the jwt
	_, _, err = ExecuteCmd(createEditAccount(), "--tag", "A")
	require.NoError(t, err)

	// sync the store
	_, _, err = ExecuteCmd(createPushCmd(), "--account", "A")
	require.NoError(t, err)

	// verify the tag was stored
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "a")
}

func Test_SyncNoURL(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp)
	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	ts.AddAccount(t, "A")
	as.Close()

	// remove the account server so we cannot push
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oc.AccountServerURL = ""
	token, err := oc.Encode(okp)
	require.NoError(t, err)
	ts.Store.StoreClaim([]byte(token))

	_, _, err = ExecuteCmd(createPushCmd(), "--account", "A")
	require.Error(t, err)
	t.Log(err.Error())
	require.Contains(t, err.Error(), "no account server url was provided by the operator jwt")
}

func Test_SyncNoServer(t *testing.T) {
	as, m := RunTestAccountServer(t)
	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	ts.AddAccount(t, "A")
	as.Close()

	_, stderr, err := ExecuteCmd(createPushCmd(), "--account", "A")
	require.Error(t, err)
	if runtime.GOOS == "windows" {
		require.Contains(t, stderr, "connectex: No connection")
	} else {
		require.Contains(t, stderr, "connect: connection refused")
	}
}

func Test_SyncManaged(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.False(t, ac.IsSelfSigned())
}
