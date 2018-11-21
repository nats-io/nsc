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

func Test_AddExport(t *testing.T) {
	ts := NewTestStore(t, "add_export")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", "A")
	require.NoError(t, err, "export creation")

	tests := CmdTests{
		{createAddExportCmd(), []string{"add", "export"}, nil, []string{"subject is required"}, true},
		{createAddExportCmd(), []string{"add", "export", "--subject", "foo"}, nil, []string{"added public stream export \"foo\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "bar", "--service"}, nil, []string{"added public service export \"bar\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "bar"}, nil, []string{"export subject \"bar\" already exports \"bar\""}, true},
		{createAddExportCmd(), []string{"add", "export", "--subject", "foo", "--service"}, nil, []string{"export subject \"foo\" already exports \"foo\""}, true},
		{createAddExportCmd(), []string{"add", "export", "--subject", "baz.>", "--service"}, nil, []string{"services cannot have wildcard subject: \"baz.>\""}, true},
		{createAddExportCmd(), []string{"add", "export", "--subject", "baz.>"}, nil, []string{"added public stream export \"baz.>\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "ar", "--name", "mar"}, nil, []string{"added public stream export \"mar\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "mar", "--name", "ar", "--service"}, nil, []string{"added public service export \"ar\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "pubstream", "--private"}, nil, []string{"added private stream export \"pubstream\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "pubservice", "--private", "--service"}, nil, []string{"added private service export \"pubservice\""}, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddExportVerify(t *testing.T) {
	ts := NewTestStore(t, "add_export")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", "A")
	require.NoError(t, err, "export creation")

	tests := CmdTests{
		{createAddExportCmd(), []string{"add", "export", "--subject", "pubfoo"}, nil, []string{"added public stream export \"pubfoo\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "privfoo", "--private"}, nil, []string{"added private stream export \"privfoo\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "pubbar", "--service"}, nil, []string{"added public service export \"pubbar\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "privbar", "--service", "--private"}, nil, []string{"added private service export \"privbar\""}, false},
	}
	tests.Run(t, "root", "add")
	validateAddExports(t, ts)
}

func validateAddExports(t *testing.T, ts *TestStore) {
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)

	require.Len(t, ac.Exports, 4)

	pubfoo := ac.Exports[0]
	require.Equal(t, "pubfoo", pubfoo.Name)
	require.Equal(t, "pubfoo", string(pubfoo.Subject))
	require.Equal(t, jwt.Stream, pubfoo.Type)
	require.False(t, pubfoo.TokenReq)

	privfoo := ac.Exports[1]
	require.Equal(t, "privfoo", privfoo.Name)
	require.Equal(t, "privfoo", string(privfoo.Subject))
	require.Equal(t, jwt.Stream, privfoo.Type)
	require.True(t, privfoo.TokenReq)

	pubbar := ac.Exports[2]
	require.Equal(t, "pubbar", pubbar.Name)
	require.Equal(t, "pubbar", string(pubbar.Subject))
	require.Equal(t, jwt.Service, pubbar.Type)
	require.False(t, pubbar.TokenReq)

	privbar := ac.Exports[3]
	require.Equal(t, "privbar", privbar.Name)
	require.Equal(t, "privbar", string(privbar.Subject))
	require.Equal(t, jwt.Service, privbar.Type)
	require.True(t, privbar.TokenReq)
}

func Test_AddExportOperatorLessStore(t *testing.T) {
	ts := NewTestStoreWithOperator(t, "test", nil)
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", "A", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createAddExportCmd(), "--subject", "aaaa")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, "aaaa", string(ac.Exports[0].Subject))
}
