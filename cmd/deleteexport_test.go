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

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func Test_DeleteExport(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo", true)
	ts.AddExport(t, "A", jwt.Stream, "baz", true)
	ts.AddExport(t, "B", jwt.Service, "bar", true)

	tests := CmdTests{
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "A"}, nil, []string{"subject is required"}, true},
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "A", "--subject", "a"}, nil, []string{"no export matching \"a\" found"}, true},
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "A", "--subject", "foo"}, nil, []string{"deleted export of \"foo\""}, false},
		{createDeleteExportCmd(), []string{"delete", "export", "--account", "B"}, nil, []string{"deleted export of \"bar\""}, false},
	}

	tests.Run(t, "root", "delete")
}

func Test_DeleteExportAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo", true)
	ts.AddExport(t, "B", jwt.Service, "bar", true)
	GetConfig().SetAccount("")
	_, _, err := ExecuteCmd(createDeleteExportCmd(), "--subject", "foo")
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func Test_DeleteExportInteractive(t *testing.T) {
	ts := NewTestStoreWithOperator(t, "test", nil)
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo", true)
	ts.AddExport(t, "A", jwt.Stream, "baz", true)
	ts.AddAccount(t, "B")

	input := []interface{}{0, 0, ts.KeyStore.GetAccountKeyPath("A")}
	cmd := createDeleteExportCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Exports, 1)
}
