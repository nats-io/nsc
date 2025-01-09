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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnv_DefaultOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	out, err := ExecuteCmd(createEnvCmd(), []string{}...)
	require.NoError(t, err)
	stdout := StripTableDecorations(out.Out)
	require.NoError(t, err)
	require.Contains(t, stdout, fmt.Sprintf("$NKEYS_PATH (deprecated) Yes %s", AbbrevHomePaths(store.GetKeysDir())))
	require.Contains(t, stdout, fmt.Sprintf("Current Store Dir %s", AbbrevHomePaths(filepath.Dir(ts.Store.Dir))))
	require.Contains(t, stdout, "Current Operator test")
}

func TestEnv_SetAccountOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	out, err := ExecuteCmd(createEnvCmd(), []string{"--operator", "test", "--account", "B"}...)
	require.NoError(t, err)
	stdout := StripTableDecorations(out.Out)
	require.Contains(t, stdout, fmt.Sprintf("$NKEYS_PATH (deprecated) Yes %s", AbbrevHomePaths(store.GetKeysDir())))
	require.Contains(t, stdout, fmt.Sprintf("Current Store Dir %s", AbbrevHomePaths(filepath.Dir(ts.Store.Dir))))
	require.Contains(t, stdout, "Current Operator test")
	require.Contains(t, stdout, "Current Account B")
}

func TestEnv_FailsBadOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEnvCmd(), []string{"-o", "X"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "operator \"X\" not in")
}

func TestEnv_FailsBadAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEnvCmd(), []string{"-a", "A"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"A\" not in accounts for operator \"O\"")
}

func TestAllDir(t *testing.T) {
	p := MakeTempDir(t)
	defer os.RemoveAll(p)

	_, err := ExecuteCmd(rootCmd, []string{"env", "--all-dirs", p}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(rootCmd, []string{"add", "operator", "O", "--all-dirs", p}...)
	require.NoError(t, err)

	assert.FileExists(t, path.Join(p, "nsc.json"))
	assert.DirExists(t, path.Join(p, "creds"))
	assert.DirExists(t, path.Join(p, "keys"))
	assert.DirExists(t, path.Join(p, "O"))
}
