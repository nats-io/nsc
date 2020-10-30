/*
 * Copyright 2018-2020 The NATS Authors
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
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func TestRevokeListActivation(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", false)
	ts.AddExport(t, "A", jwt.Service, "bar", false)
	ts.AddExport(t, "A", jwt.Service, "public", true) // we support revoking public exports

	_, pub, _ := CreateAccountKey(t)

	_, _, err := ExecuteCmd(createRevokeActivationCmd(), "--subject", "foo.bar", "--target-account", pub)
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createRevokeActivationCmd(), "--subject", "bar", "--target-account", pub, "--service", "--at", "1001")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createRevokeActivationCmd(), "--subject", "public", "--target-account", pub, "--service", "--at", "2001")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createRevokeListActivationCmd(), "--subject", "foo.bar")
	require.NoError(t, err)

	require.True(t, strings.Contains(stdout, pub))
	require.False(t, strings.Contains(stdout, time.Unix(1001, 0).Format(time.RFC1123)))
	require.False(t, strings.Contains(stdout, time.Unix(2001, 0).Format(time.RFC1123)))

	stdout, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--subject", "bar", "--service")
	require.NoError(t, err)

	require.True(t, strings.Contains(stdout, pub))
	require.True(t, strings.Contains(stdout, time.Unix(1001, 0).Format(time.RFC1123)))
	require.False(t, strings.Contains(stdout, time.Unix(2001, 0).Format(time.RFC1123)))

	stdout, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--subject", "public", "--service")
	require.NoError(t, err)

	require.True(t, strings.Contains(stdout, pub))
	require.False(t, strings.Contains(stdout, time.Unix(1001, 0).Format(time.RFC1123)))
	require.True(t, strings.Contains(stdout, time.Unix(2001, 0).Format(time.RFC1123)))
}

func TestRevokeListActivationNoAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	_, _, err := ExecuteInteractiveCmd(createRevokeListActivationCmd(), []interface{}{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no accounts defined")
}

func TestRevokeListActivationNoAccountInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createRevokeListActivationCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "an account is required")
}

func TestRevokeListActivationNoExport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createRevokeListActivationCmd(), "--service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have exports")
}

func TestRevokeListActivationNoServiceExport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "s", false)
	_, _, err := ExecuteCmd(createRevokeListActivationCmd(), "--service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have service exports")
}

func TestRevokeListActivationNoStreamExport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "s", false)
	_, _, err := ExecuteCmd(createRevokeListActivationCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have stream exports")
}

func TestRevokeListActivationDefaultExport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "s", false)
	_, _, err := ExecuteCmd(createRevokeActivationCmd(), "--service", "--target-account", "*")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--service")
	require.NoError(t, err)
}

func TestRevokeListActivationNoDefaultExport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "s", false)
	ts.AddExport(t, "A", jwt.Service, "r", false)
	_, _, err := ExecuteCmd(createRevokeActivationCmd(), "--service", "--target-account", "*", "--subject", "s")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createRevokeActivationCmd(), "--service", "--target-account", "*", "--subject", "r")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--service")
	require.Error(t, err)
	require.Contains(t, err.Error(), "a subject is required")
}

func TestRevokeListActivationExportNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "s", false)
	ts.AddExport(t, "A", jwt.Service, "r", false)
	_, _, err := ExecuteCmd(createRevokeActivationCmd(), "--service", "--target-account", "*", "--subject", "s")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createRevokeActivationCmd(), "--service", "--target-account", "*", "--subject", "r")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--service", "--subject", "x")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to locate export")
}

func TestRevokeListActivationHasNoRevocations(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "s", false)
	_, _, err := ExecuteCmd(createRevokeListActivationCmd(), "--service", "--subject", "s")
	require.Error(t, err)
	require.Contains(t, err.Error(), "service s has no revocations")
}

func TestRevokeListActivationInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "s", false)
	_, _, err := ExecuteCmd(createRevokeActivationCmd(), "--service", "--subject", "s", "--target-account", "*")
	args := []interface{}{true, 0}
	_, _, err = ExecuteInteractiveCmd(createRevokeListActivationCmd(), args)
	require.NoError(t, err)
}
