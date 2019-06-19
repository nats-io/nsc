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
	"fmt"
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestEnv_DefaultOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, stderr, err := ExecuteCmd(createEnvCmd())
	require.NoError(t, err)
	stderr = StripTableDecorations(stderr)
	require.Contains(t, stderr, fmt.Sprintf("$NKEYS_PATH Yes %s", store.GetKeysDir()))
	require.Contains(t, stderr, fmt.Sprintf("Stores Dir %s", filepath.Dir(ts.Store.Dir)))
	require.Contains(t, stderr, "Default Operator test")
}

func TestEnv_SetAccountOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, stderr, err := ExecuteCmd(createEnvCmd(), "--operator", "test", "--account", "B")
	require.NoError(t, err)
	stderr = StripTableDecorations(stderr)
	require.Contains(t, stderr, fmt.Sprintf("$NKEYS_PATH Yes %s", store.GetKeysDir()))
	require.Contains(t, stderr, fmt.Sprintf("Stores Dir %s", filepath.Dir(ts.Store.Dir)))
	require.Contains(t, stderr, "Default Operator test")
	require.Contains(t, stderr, "Default Account B")
}

func TestEnv_FailsBadOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createEnvCmd(), "-o", "X")
	require.Error(t, err)
	require.Contains(t, err.Error(), "operator \"X\" not in")
}

func TestEnv_FailsBadAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createEnvCmd(), "-a", "A")
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"A\" not in accounts for operator \"O\"")
}
