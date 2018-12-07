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

func TestDescribeCluster_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	opub, err := ts.KeyStore.GetOperatorPublicKey("operator")
	require.NoError(t, err)

	ts.AddCluster(t, "A")

	pub, err := ts.KeyStore.GetClusterPublicKey("A")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeClusterCmd())
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, opub)
	require.Contains(t, stdout, " A ")
}

func TestDescribeCluster_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")

	out, _, err := ExecuteCmd(createDescribeClusterCmd())
	require.NoError(t, err)
	require.Contains(t, StripTableDecorations(out), "Name B")
}

func TestDescribeCluster_MultipleAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")
	GetConfig().SetCluster("")

	_, _, err := ExecuteCmd(createDescribeClusterCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "cluster is required")
}

func TestDescribeCluster_MultipleWithContext(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")

	err := GetConfig().SetCluster("B")
	require.NoError(t, err)

	pub, err := ts.KeyStore.GetClusterPublicKey("B")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeClusterCmd())
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " B ")
}

func TestDescribeCluster_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")

	pub, err := ts.KeyStore.GetClusterPublicKey("B")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeClusterCmd(), "--cluster", "B")
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " B ")
}

func TestDescribeCluster_MultipleWithBadAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")

	_, _, err := ExecuteCmd(createDescribeClusterCmd(), "--cluster", "C")
	require.Error(t, err)
}

func TestDescribeCluster_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")

	_, _, err := ExecuteInteractiveCmd(createDescribeClusterCmd(), []interface{}{0})
	require.NoError(t, err)
}
