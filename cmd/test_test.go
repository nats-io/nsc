// Copyright 2025-2025 The NATS Authors
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
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func Test_FlagTable(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(GetRootCmd(), "test", "flags")
	require.NoError(t, err)
	require.Contains(t, out.Out, "nsc validate")
	require.Contains(t, out.Out, "nsc add account")
}

func Test_WhoFlagTable(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(GetRootCmd(), "test", "whoflag", "allow-pub")
	require.NoError(t, err)
	require.Contains(t, out.Out, "nsc add user")
}

func Test_Doc(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	docs := filepath.Join(ts.Dir, "doc")
	_, err := ExecuteCmd(GetRootCmd(), []string{"test", "doc", docs}...)
	require.NoError(t, err)
	require.DirExists(t, docs)
	require.FileExists(t, filepath.Join(docs, "nsc_add.md"))
	require.FileExists(t, filepath.Join(docs, "nsc_validate.md"))
}
