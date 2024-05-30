/*
 * Copyright 2019 The NATS Authors
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
	"os"
	"testing"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_DeleteUserNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, _, err := ExecuteCmd(createDeleteUserCmd(), "--name", "X")
	require.Error(t, err)
	_, ok := err.(*store.ResourceErr)
	require.True(t, ok)
}

func Test_DeleteUserOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--name", "U")
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.Error(t, err)
	require.Nil(t, uc)

	require.True(t, ts.KeyStore.HasPrivateKey(upk))
	require.FileExists(t, ts.KeyStore.GetUserCredsPath("A", "U"))
}

func Test_DeleteUserAll(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--name", "U", "--rm-nkey", "--rm-creds")
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.Error(t, err)
	require.Nil(t, uc)

	require.False(t, ts.KeyStore.HasPrivateKey(upk))
	_, err = os.Stat(ts.KeyStore.GetUserCredsPath("A", "U"))
	require.True(t, os.IsNotExist(err))
}

func Test_DeleteUserInvalidate(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--name", "U", "--revoke")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, ac.Revocations[upk] > 0)
}

func Test_DeleteUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, _, err = ExecuteInteractiveCmd(createDeleteUserCmd(), []interface{}{[]int{0}, true, true, true, true})
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.Error(t, err)
	require.Nil(t, uc)

	require.False(t, ts.KeyStore.HasPrivateKey(upk))
	_, err = os.Stat(ts.KeyStore.GetUserCredsPath("A", "U"))
	require.True(t, os.IsNotExist(err))
}

func Test_DeleteUserFromDiffAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	ts.AddAccount(t, "B")

	_, _, err := ExecuteCmd(createDeleteUserCmd(), "a", "-a", "A")
	require.NoError(t, err)

	_, err = ts.Store.ReadUserClaim("A", "a")
	require.Error(t, err)
}

func Test_DeleteUserFromDiffAccountInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	ts.AddAccount(t, "B")

	uc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	upk := uc.Subject

	_, _, err = ExecuteInteractiveCmd(createDeleteUserCmd(), []interface{}{0, []int{0}, true, true, true, true})
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "a")
	require.Error(t, err)
	require.Nil(t, uc)

	require.False(t, ts.KeyStore.HasPrivateKey(upk))
	_, err = os.Stat(ts.KeyStore.GetUserCredsPath("A", "a"))
	require.True(t, os.IsNotExist(err))
}

//func Test_RevokeUserRequiresOperatorKey(t *testing.T) {
//	ts := NewTestStore(t, "O")
//	defer ts.Done(t)
//
//	ts.AddAccount(t, "A")
//	ts.AddUser(t, "A", "U")
//
//	_, err := ts.Store.ReadUserClaim("A", "U")
//	require.NoError(t, err)
//
//	opk, err := ts.Store.GetRootPublicKey()
//	require.NoError(t, err)
//	require.NoError(t, ts.KeyStore.Remove(opk))
//
//	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--name", "U", "--revoke")
//	require.Error(t, err)
//
//	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--name", "U")
//	require.NoError(t, err)
//}
