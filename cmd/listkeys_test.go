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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nats-io/nsc/v2/cmd/store"

	"github.com/stretchr/testify/require"
)

func Test_ListKeysDefault(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	out, err := ExecuteCmd(createListKeysCmd())
	require.NoError(t, err)
	stderr := StripTableDecorations(out.Out)

	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "O", ts.GetOperatorPublicKey(t)))
	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "A", ts.GetAccountPublicKey(t, "A")))
	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "U", ts.GetUserPublicKey(t, "A", "U")))
}

func Test_listKeysOperatorOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	out, err := ExecuteCmd(createListKeysCmd(), "--operator")
	require.NoError(t, err)
	stderr := StripTableDecorations(out.Out)

	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "O", ts.GetOperatorPublicKey(t)))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "A", ts.GetAccountPublicKey(t, "A")))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "U", ts.GetUserPublicKey(t, "A", "U")))
}

func Test_listKeysAccountOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	out, err := ExecuteCmd(createListKeysCmd(), "--accounts")
	require.NoError(t, err)
	stderr := StripTableDecorations(out.Out)

	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "O", ts.GetOperatorPublicKey(t)))
	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "A", ts.GetAccountPublicKey(t, "A")))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "U", ts.GetUserPublicKey(t, "A", "U")))
}

func Test_ListKeysUserOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	out, err := ExecuteCmd(createListKeysCmd(), "--users")
	require.NoError(t, err)
	stderr := StripTableDecorations(out.Out)

	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "O", ts.GetOperatorPublicKey(t)))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "A", ts.GetAccountPublicKey(t, "A")))
	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "U", ts.GetUserPublicKey(t, "A", "U")))
}

func Test_ListKeysOther(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, pk, kp := CreateOperatorKey(t)
	_, err := ts.KeyStore.Store(kp)
	require.NoError(t, err)

	out, err := ExecuteCmd(createListKeysCmd(), "--all", "--not-referenced")
	require.NoError(t, err)
	stderr := StripTableDecorations(out.Out)

	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "O", ts.GetOperatorPublicKey(t)))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "A", ts.GetAccountPublicKey(t, "A")))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "U", ts.GetUserPublicKey(t, "A", "U")))
	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "?", pk))
}

func Test_ListKeysFilter(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	opk := ts.GetOperatorPublicKey(t)

	out, err := ExecuteCmd(createListKeysCmd(), "--all", "--filter", opk[:10])
	require.NoError(t, err)
	stderr := StripTableDecorations(out.Out)

	require.Contains(t, stderr, fmt.Sprintf("%s %s *", "O", opk))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "A", ts.GetAccountPublicKey(t, "A")))
	require.NotContains(t, stderr, fmt.Sprintf("%s %s *", "U", ts.GetUserPublicKey(t, "A", "U")))
}

func Test_ListKeysNoKeyStore(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	old := store.KeyStorePath
	store.KeyStorePath = ts.KeysDir
	_, err := ExecuteCmd(createListKeysCmd())
	require.Error(t, err)
	require.Equal(t, err.Error(), fmt.Sprintf("keystore `%s` does not exist", ts.KeysDir))
	store.KeyStorePath = old
}

func Test_listKeysAuthorizationXKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, uPK, _ := CreateUserKey(t)
	_, err := ExecuteCmd(createEditAuthorizationCallout(), "--auth-user", uPK, "--curve", "generate")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	xPK := ac.Authorization.XKey
	require.NotEmpty(t, xPK)

	out, err := ExecuteCmd(createListKeysCmd(), "-A")
	require.NoError(t, err)
	stdout := StripTableDecorations(out.Out)
	require.Contains(t, stdout, xPK)

	_, err = ExecuteCmd(createEditAuthorizationCallout(), "--rm-curve")
	require.NoError(t, err)

	out, err = ExecuteCmd(createListKeysCmd(), "-A")
	require.NoError(t, err)
	stdout = StripTableDecorations(out.Out)
	require.NotContains(t, stdout, xPK)

	out, err = ExecuteCmd(createListKeysCmd(), "--not-referenced")
	require.NoError(t, err)
	stdout = StripTableDecorations(out.Out)
	require.Contains(t, stdout, xPK)
}

func Test_ListKeysJson(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	out, err := ExecuteCmd(createListKeysCmd(), "--json")
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	apk := ts.GetAccountPublicKey(t, "A")
	upk := ts.GetUserPublicKey(t, "A", "U")

	var keys []keyForJson
	require.NoError(t, json.Unmarshal([]byte(out.Out), &keys))

	require.Len(t, keys, 3)

	require.Equal(t, "O", keys[0].Key.Name)
	require.Equal(t, opk, keys[0].Key.Pub)
	require.Equal(t, "operator", keys[0].ExpectedKind)
	require.Equal(t, "", keys[0].Seed)

	require.Equal(t, "A", keys[1].Key.Name)
	require.Equal(t, apk, keys[1].Key.Pub)
	require.Equal(t, "account", keys[1].ExpectedKind)
	require.Equal(t, "", keys[1].Seed)

	require.Equal(t, "U", keys[2].Key.Name)
	require.Equal(t, upk, keys[2].Key.Pub)
	require.Equal(t, "user", keys[2].ExpectedKind)
	require.Equal(t, "", keys[2].Seed)
}

func TestListKeysJsonWithSeeds(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	out, err := ExecuteCmd(createListKeysCmd(), "--json", "--show-seeds")
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	opSeed, err := ts.KeyStore.GetSeed(opk)
	require.NoError(t, err)

	apk := ts.GetAccountPublicKey(t, "A")
	apkSeed, err := ts.KeyStore.GetSeed(apk)
	require.NoError(t, err)

	upk := ts.GetUserPublicKey(t, "A", "U")
	upkSeed, err := ts.KeyStore.GetSeed(upk)
	require.NoError(t, err)

	var keys []keyForJson
	require.NoError(t, json.Unmarshal([]byte(out.Out), &keys))

	require.Len(t, keys, 3)

	require.Equal(t, "O", keys[0].Key.Name)
	require.Equal(t, opk, keys[0].Key.Pub)
	require.Equal(t, "operator", keys[0].ExpectedKind)
	require.Equal(t, opSeed, keys[0].Seed)

	require.Equal(t, "A", keys[1].Key.Name)
	require.Equal(t, apk, keys[1].Key.Pub)
	require.Equal(t, "account", keys[1].ExpectedKind)
	require.Equal(t, apkSeed, keys[1].Seed)

	require.Equal(t, "U", keys[2].Key.Name)
	require.Equal(t, upk, keys[2].Key.Pub)
	require.Equal(t, "user", keys[2].ExpectedKind)
	require.Equal(t, upkSeed, keys[2].Seed)
}
