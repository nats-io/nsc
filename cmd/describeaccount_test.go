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

func TestDescribeAccount_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	opub, err := ts.KeyStore.GetOperatorPublicKey("operator")
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	pub, err := ts.KeyStore.GetAccountPublicKey("A")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	// account A public key
	require.Contains(t, stdout, pub)
	// operator public key
	require.Contains(t, stdout, opub)
	// name for the account
	require.Contains(t, stdout, " A ")
}

func TestDescribeAccount_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	out, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	out = StripTableDecorations(out)
	require.Contains(t, out, "Name B")
}

func TestDescribeAccount_MultipleAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	GetConfig().SetAccount("")

	_, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func TestDescribeAccount_MultipleWithContext(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	err := GetConfig().SetAccount("B")
	require.NoError(t, err)

	opub, err := ts.KeyStore.GetOperatorPublicKey("operator")
	require.NoError(t, err)

	pub, err := ts.KeyStore.GetAccountPublicKey("B")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, opub)
	require.Contains(t, stdout, " B ")
}

func TestDescribeAccount_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	pub, err := ts.KeyStore.GetAccountPublicKey("B")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createDescribeAccountCmd(), "--account", "B")
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " B ")
}

func TestDescribeAccount_MultipleWithBadAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, _, err := ExecuteCmd(createDescribeAccountCmd(), "--account", "C")
	require.Error(t, err)
}

func TestDescribeAccount_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, _, err := ExecuteInteractiveCmd(createDescribeAccountCmd(), []interface{}{0})
	require.NoError(t, err)
}
