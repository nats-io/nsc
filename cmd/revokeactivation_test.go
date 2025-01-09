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
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRevokeActivation(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, false)
	ts.AddExport(t, "A", jwt.Service, "bar", 0, false)
	ts.AddExport(t, "A", jwt.Service, "public", 0, true) // we support revoking public exports

	_, pub, _ := CreateAccountKey(t)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"--subject", "foo.bar", "--target-account", pub}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createRevokeActivationCmd(), []string{"--subject", "bar", "--target-account", pub, "--service"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createRevokeActivationCmd(), []string{"--subject", "public", "--target-account", pub, "--service"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 3)

	for _, exp := range ac.Exports {
		require.True(t, exp.Revocations.IsRevoked(pub, time.Unix(0, 0)))
	}
}

func TestRevokeActivationAt(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, false)
	ts.AddExport(t, "A", jwt.Service, "bar", 0, false)

	_, pub, _ := CreateAccountKey(t)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"--subject", "foo.bar", "--target-account", pub, "--at", "1000"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createRevokeActivationCmd(), []string{"--subject", "bar", "--target-account", pub, "--service", "--at", "1000"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 2)

	for _, exp := range ac.Exports {
		require.True(t, exp.Revocations.IsRevoked(pub, time.Unix(999, 0)))
		require.False(t, exp.Revocations.IsRevoked(pub, time.Unix(1001, 0)))
	}
}

func TestRevokeActivationForStreamInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, false)
	ts.AddExport(t, "A", jwt.Service, "bar", 0, false)
	ts.AddAccount(t, "B")
	ts.AddExport(t, "B", jwt.Stream, "foo.>", 0, false)
	ts.AddExport(t, "B", jwt.Service, "bar", 0, false)

	_, pub, _ := CreateAccountKey(t)

	input := []interface{}{1, false, 0, pub, "1000"} // second account "B"
	cmd := createRevokeActivationCmd()
	HoistRootFlags(cmd)
	_, err := ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	for _, exp := range ac.Exports {
		require.Len(t, exp.Revocations, 0)
	}

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)

	for _, exp := range ac.Exports {
		if exp.Subject != "foo.>" {
			require.Len(t, exp.Revocations, 0)
			continue
		}
		require.Len(t, exp.Revocations, 1)
		require.True(t, exp.Revocations.IsRevoked(pub, time.Unix(999, 0)))
		require.False(t, exp.Revocations.IsRevoked(pub, time.Unix(1001, 0)))
	}
}

func TestRevokeActivationForServiceInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, false)
	ts.AddExport(t, "A", jwt.Service, "bar", 0, false)
	ts.AddAccount(t, "B")
	ts.AddExport(t, "B", jwt.Stream, "foo.>", 0, false)
	ts.AddExport(t, "B", jwt.Service, "bar", 0, false)

	_, pub, _ := CreateAccountKey(t)

	input := []interface{}{1, true, 0, pub, "1000"} // second account "B"
	cmd := createRevokeActivationCmd()
	HoistRootFlags(cmd)
	_, err := ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	for _, exp := range ac.Exports {
		require.Len(t, exp.Revocations, 0)
	}

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)

	for _, exp := range ac.Exports {
		if exp.Subject != "bar" {
			require.Len(t, exp.Revocations, 0)
			continue
		}
		require.Len(t, exp.Revocations, 1)
		require.True(t, exp.Revocations.IsRevoked(pub, time.Unix(999, 0)))
		require.False(t, exp.Revocations.IsRevoked(pub, time.Unix(1001, 0)))
	}
}

func TestRevokeActivationNoExports(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have exports")
}

func TestRevokeActivationServiceNoExports(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have stream exports")
}

func TestRevokeActivationStreamNoExports(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "q", 0, false)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*", "--service"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have service exports")
}

func TestRevokeActivationSubjectRequired(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)
	ts.AddExport(t, "A", jwt.Service, "qq", 0, false)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*", "--service"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "a subject is required")
}

func TestRevokeActivationExportNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*", "--service", "--subject", "foo"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to locate export")
}

func TestRevokeActivationDefaultSubject(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*", "--service"}...)
	require.NoError(t, err)
}

func TestRevokeActivationAll(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)

	_, err := ExecuteCmd(createRevokeActivationCmd(), []string{"-t", "*", "--service", "--subject", "q"}...)
	require.NoError(t, err)
}

func TestRevokeActivationBadInteractiveAt(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)

	input := []interface{}{true, 0, "*", "hello"}
	_, err := ExecuteInteractiveCmd(createRevokeActivationCmd(), input)
	require.Error(t, err)
	require.Contains(t, err.Error(), `provided value "hello" is not`)
}
