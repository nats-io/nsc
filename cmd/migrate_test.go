// Copyright 2018-2025 The NATS Authors
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

package cmd

import (
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_Migrate(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")

	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")

	ts.AddOperator(t, "OO")
	_, err := ExecuteCmd(createMigrateCmd(), []string{"--url", filepath.Join(ts.GetStoresRoot(), "O", "accounts", "A", "A.jwt")}...)
	require.NoError(t, err)

	oos, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), "OO"))
	require.NoError(t, err)
	_, err = oos.ReadAccountClaim("A")
	require.NoError(t, err)
	_, err = oos.ReadUserClaim("A", "a")
	require.NoError(t, err)
}

func Test_MigrateMany(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")

	ts.AddOperator(t, "OO")
	_, err := ExecuteCmd(createMigrateCmd(), []string{"--operator-dir", filepath.Join(ts.GetStoresRoot(), "O")}...)
	require.NoError(t, err)

	oos, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), "OO"))
	require.NoError(t, err)
	_, err = oos.ReadAccountClaim("A")
	require.NoError(t, err)
	_, err = oos.ReadUserClaim("A", "a")
	require.NoError(t, err)
	_, err = oos.ReadAccountClaim("B")
	require.NoError(t, err)
	_, err = oos.ReadUserClaim("B", "b")
	require.NoError(t, err)
}

func Test_MigrateSingleInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")
	ts.AddOperator(t, "OO")

	args := []interface{}{false, filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", "A.jwt")}
	_, err := ExecuteInteractiveCmd(createMigrateCmd(), args)
	require.NoError(t, err)

	oos, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), "OO"))
	require.NoError(t, err)
	_, err = oos.ReadAccountClaim("A")
	require.NoError(t, err)
	_, err = oos.ReadUserClaim("A", "a")
	require.NoError(t, err)
}

func Test_MigrateManaged(t *testing.T) {
	_, opk, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2})
	defer as.Close()

	// create the managed operator store
	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	// add a local operator with account/user
	ts.AddOperator(t, "O")
	ts.AddAccount(t, "A")
	apk := ts.GetAccountPublicKey(t, "A")
	ts.AddUser(t, "A", "U")

	// switch back to managed
	ts.SwitchOperator(t, "T")

	// migrate the local operator
	_, err := ExecuteCmd(createMigrateCmd(), []string{"--operator-dir", filepath.Join(ts.StoreDir, "O")}...)
	require.NoError(t, err)
	require.NotNil(t, m[apk])

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, opk, ac.Issuer)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc)
}
