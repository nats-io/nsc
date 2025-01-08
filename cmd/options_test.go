/*
 * Copyright 2020-2025 The NATS Authors
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
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestNoGitIgnore(t *testing.T) {
	require.NoError(t, os.Setenv(NscNoGitIgnoreEnv, "true"))
	defer func() {
		require.NoError(t, os.Unsetenv(NscNoGitIgnoreEnv))
	}()
	SetEnvOptions()
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.DoesNotExist(t, filepath.Join(ts.Dir, "keys", ".gitignore"))
}

func TestCwdOnly(t *testing.T) {
	require.NoError(t, os.Setenv(NscCwdOnlyEnv, "true"))
	defer func() {
		require.NoError(t, os.Unsetenv(NscCwdOnlyEnv))
	}()
	SetEnvOptions()
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(GetRootCmd(), "env")
	require.NoError(t, err)
	require.Contains(t, StripTableDecorations(out.Out), "$NSC_CWD_ONLY Yes")

	_, err = ExecuteCmd(createEnvCmd(), []string{"--account", "A"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "$NSC_CWD_ONLY is set")
}
