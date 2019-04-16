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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescribeServer_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddServer(t, "A", "a")

	pub, err := ts.KeyStore.GetServerPublicKey("A", "a")
	require.NoError(t, err)

	cpub, err := ts.KeyStore.GetClusterPublicKey("A")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeServerCmd())
	require.NoError(t, err)
	// account A public key
	require.Contains(t, stdout, cpub)
	// operator public key
	require.Contains(t, stdout, pub)
	// name for the account
	require.Contains(t, stdout, " a ")
}

func TestDescribeServer_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddServer(t, "A", "a")
	ts.AddServer(t, "A", "b")

	_, stderr, err := ExecuteCmd(createDescribeServerCmd())
	require.Error(t, err)
	require.Contains(t, stderr, "server is required")
}

func TestDescribeServer_MultipleWithContext(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddServer(t, "A", "a")
	ts.AddCluster(t, "B")
	ts.AddServer(t, "B", "b")

	err := GetConfig().SetCluster("B")
	require.NoError(t, err)

	cpub, err := ts.KeyStore.GetClusterPublicKey("B")
	require.NoError(t, err)

	pub, err := ts.KeyStore.GetServerPublicKey("B", "b")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeServerCmd())
	require.NoError(t, err)
	require.Contains(t, stdout, cpub)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " b ")
}

func TestDescribeServer_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")
	ts.AddServer(t, "B", "b")
	ts.AddServer(t, "B", "bb")

	_, stderr, err := ExecuteCmd(createDescribeServerCmd(), "--cluster", "B")
	require.Error(t, err)
	require.Contains(t, stderr, "server is required")

	cpub, err := ts.KeyStore.GetClusterPublicKey("B")
	require.NoError(t, err)

	pub, err := ts.KeyStore.GetServerPublicKey("B", "bb")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeServerCmd(), "--cluster", "B", "--server", "bb")
	require.NoError(t, err)
	require.Contains(t, stdout, cpub)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " bb ")
}

func TestDescribeServer_MultipleWithBadUser(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")
	ts.AddServer(t, "B", "b")

	_, _, err := ExecuteCmd(createDescribeServerCmd(), "--cluster", "A")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createDescribeServerCmd(), "--cluster", "B", "--server", "a")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createDescribeServerCmd(), "--cluster", "B", "--server", "b")
	require.NoError(t, err)
}

func TestDescribeServer_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")
	ts.AddServer(t, "B", "bb")

	_, _, err := ExecuteInteractiveCmd(createDescribeServerCmd(), []interface{}{1, 0})
	require.NoError(t, err)
}
