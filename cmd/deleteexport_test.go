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
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_DeleteExport(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo", 0, true)
	ts.AddExport(t, "A", jwt.Stream, "baz", 0, true)
	ts.AddExport(t, "B", jwt.Service, "bar", 0, true)

	tests := CmdTests{
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "A"}, nil, []string{"subject is required"}, true},
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "A", "--subject", "a"}, nil, []string{"no export matching \"a\" found"}, true},
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "A", "--subject", "foo"}, []string{"deleted stream export \"foo\""}, nil, false},
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "B"}, []string{"deleted service export \"bar\""}, nil, false},
	}

	tests.Run(t, "root", "delete")
}

func Test_DeleteExportAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo", 0, true)
	ts.AddExport(t, "B", jwt.Service, "bar", 0, true)
	GetConfig().SetAccount("")
	_, err := ExecuteCmd(createDeleteExportCmd(), []string{"--subject", "foo"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func Test_DeleteExportInteractiveManagedStore(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo", 0, true)
	ts.AddExport(t, "A", jwt.Stream, "baz", 0, true)
	ts.AddAccount(t, "B")

	cmd := createDeleteExportCmd()
	HoistRootFlags(cmd)

	input := []interface{}{0, 0, 0, ts.GetAccountKeyPath(t, "A")}
	_, err := ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
}
