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
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"

	"github.com/stretchr/testify/require"
)

func TestDescribe(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, serr, err := ExecuteCmd(createDescribeCmd())
	require.Error(t, err)
	require.Contains(t, serr, "file is required")
}

func TestDescribe_Operator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	pub, err := ts.KeyStore.GetOperatorPublicKey("O")

	fp := filepath.Join(ts.GetStoresRoot(), "O", "O.jwt")
	out, _, err := ExecuteCmd(createDescribeCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Interactive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	pub, err := ts.KeyStore.GetAccountPublicKey("A")
	require.NoError(t, err)

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", "A.jwt")

	out, _, err := ExecuteInteractiveCmd(createDescribeCmd(), []interface{}{fp})
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Account(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	pub, err := ts.KeyStore.GetAccountPublicKey("A")
	require.NoError(t, err)

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", "A.jwt")
	out, _, err := ExecuteCmd(createDescribeCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_User(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	pub, err := ts.KeyStore.GetUserPublicKey("A", "a")
	require.NoError(t, err)

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", store.Users, "a.jwt")
	out, _, err := ExecuteCmd(createDescribeCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Cluster(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddCluster(t, "C")
	pub, err := ts.KeyStore.GetClusterPublicKey("C")
	require.NoError(t, err)

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Clusters, "C", "C.jwt")
	out, _, err := ExecuteCmd(createDescribeCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Server(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddCluster(t, "C")
	ts.AddServer(t, "C", "s")
	pub, err := ts.KeyStore.GetServerPublicKey("C", "s")
	require.NoError(t, err)

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Clusters, "C", store.Servers, "s.jwt")
	out, _, err := ExecuteCmd(createDescribeCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Activation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	ts.AddExport(t, "A", jwt.Stream, "AA.>", false)

	token := ts.GenerateActivation(t, "A", "AA.>", "B")
	tp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(tp, []byte(token)))

	out, _, err := ExecuteCmd(createDescribeCmd(), "--file", tp)
	require.NoError(t, err)
	require.Contains(t, out, "AA.>")
}
