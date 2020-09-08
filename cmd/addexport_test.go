/*
 * Copyright 2018-2019 The NATS Authors
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

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_AddExport(t *testing.T) {
	ts := NewTestStore(t, "add_export")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	tests := CmdTests{
		{createAddExportCmd(), []string{"add", "export"}, nil, []string{"subject is required"}, true},
		{createAddExportCmd(), []string{"add", "export", "--subject", "foo"}, nil, []string{"added public stream export \"foo\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "bar", "--service"}, nil, []string{"added public service export \"bar\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "bar"}, nil, []string{"added public stream export \"bar\""}, false},
		{createAddExportCmd(), []string{"add", "export", "--subject", "foo", "--service"}, nil, []string{"added public service export \"foo\""}, false},
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

	ts.AddAccount(t, "A")

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

	require.Len(t, ac.Exports, 4)
	m := make(map[string]*jwt.Export)
	for _, v := range ac.Exports {
		m[v.Name] = v
	}

	pubfoo := m["pubfoo"]
	require.NotNil(t, pubfoo)
	require.Equal(t, "pubfoo", string(pubfoo.Subject))
	require.Equal(t, jwt.Stream, pubfoo.Type)
	require.False(t, pubfoo.TokenReq)

	privfoo := m["privfoo"]
	require.NotNil(t, privfoo)
	require.Equal(t, "privfoo", string(privfoo.Subject))
	require.Equal(t, jwt.Stream, privfoo.Type)
	require.True(t, privfoo.TokenReq)

	pubbar := m["pubbar"]
	require.NotNil(t, pubbar)
	require.Equal(t, "pubbar", string(pubbar.Subject))
	require.Equal(t, jwt.Service, pubbar.Type)
	require.False(t, pubbar.TokenReq)

	privbar := m["privbar"]
	require.NotNil(t, privbar)
	require.Equal(t, "privbar", string(privbar.Subject))
	require.Equal(t, jwt.Service, privbar.Type)
	require.True(t, privbar.TokenReq)
}

func Test_AddExportManagedStore(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createAddExportCmd(), "--subject", "aaaa")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, "aaaa", string(ac.Exports[0].Subject))
}

func Test_AddExportAccountNameRequired(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	t.Log("A", ts.GetAccountPublicKey(t, "A"))
	ts.AddAccount(t, "B")
	t.Log("B", ts.GetAccountPublicKey(t, "B"))

	_, _, err := ExecuteCmd(createAddExportCmd(), "--subject", "bbbb")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, "bbbb", ac.Exports[0].Name)
}

func TestAddExportInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	input := []interface{}{0, 0, "foo.>", "Foo Stream", false, 0}
	cmd := createAddExportCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, "Foo Stream", ac.Exports[0].Name)
	require.Equal(t, "foo.>", string(ac.Exports[0].Subject))
}

func TestAddExportNonInteractive(t *testing.T) {
	ts := NewTestStore(t, t.Name())
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	cmd := createAddExportCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteCmd(cmd, "--service", "--name", "q", "--subject", "q", "--response-type", jwt.ResponseTypeChunked)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, jwt.Service, ac.Exports[0].Type)
	require.Equal(t, "q", ac.Exports[0].Name)
	require.Equal(t, "q", string(ac.Exports[0].Subject))
	require.EqualValues(t, jwt.ResponseTypeChunked, ac.Exports[0].ResponseType)
}

func TestAddServiceLatency(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	cmd := createAddExportCmd()

	_, _, err := ExecuteCmd(cmd, "--service", "--subject", "q", "--latency", "q.lat", "--sampling", "100", "--response-type", jwt.ResponseTypeStream)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, "q", string(ac.Exports[0].Subject))
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, "q.lat", string(ac.Exports[0].Latency.Results))
	require.Equal(t, 100, ac.Exports[0].Latency.Sampling)
	require.EqualValues(t, jwt.ResponseTypeStream, ac.Exports[0].ResponseType)
}

func Test_AddExportBadResponseType(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	cmd := createAddExportCmd()

	_, _, err := ExecuteCmd(cmd, "--service", "--subject", "q", "--response-type", "foo")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid response type")
}

func TestAddServiceLatencyInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	cmd := createAddExportCmd()

	// service, subject, name, private, track, freq
	args := []interface{}{1, "q", "q", false, true, "100", "q.lat", 1}
	_, _, err := ExecuteInteractiveCmd(cmd, args)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Equal(t, "q", string(ac.Exports[0].Subject))
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, "q.lat", string(ac.Exports[0].Latency.Results))
	require.Equal(t, 100, ac.Exports[0].Latency.Sampling)
	require.EqualValues(t, jwt.ResponseTypeStream, ac.Exports[0].ResponseType)
}
