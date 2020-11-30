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

func Test_EditExport_Private(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", true)

	_, _, err := ExecuteCmd(createEditExportCmd(), "--subject", "a", "--private", "--response-type", jwt.ResponseTypeChunked)
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, ac.Exports[0].TokenReq)
	require.EqualValues(t, jwt.ResponseTypeChunked, ac.Exports[0].ResponseType)
}

func Test_EditExport_Latency(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", true)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, ac.Exports[0].Latency)

	_, _, err = ExecuteCmd(createEditExportCmd(), "--subject", "a", "--sampling", "100", "--latency", "lat")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, 100, ac.Exports[0].Latency.Sampling)
	require.Equal(t, jwt.Subject("lat"), ac.Exports[0].Latency.Results)
}

func Test_EditExportInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", true)
	ts.AddExport(t, "A", jwt.Service, "b", true)

	_, _, err := ExecuteInteractiveCmd(createEditExportCmd(), []interface{}{1, 1, "c", "c", false, false, 1})
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 2)
	require.Equal(t, jwt.Subject("c"), ac.Exports[1].Subject)
	require.EqualValues(t, jwt.ResponseTypeStream, ac.Exports[1].ResponseType)
}

func Test_EditExportInteractiveLatency(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", true)

	_, _, err := ExecuteInteractiveCmd(createEditExportCmd(), []interface{}{0, 1, "c", "c", false, true, "100", "lat", 2})
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, jwt.Subject("c"), ac.Exports[0].Subject)
	require.Equal(t, "c", ac.Exports[0].Name)
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, 100, ac.Exports[0].Latency.Sampling)
	require.Equal(t, jwt.Subject("lat"), ac.Exports[0].Latency.Results)
	require.EqualValues(t, jwt.ResponseTypeChunked, ac.Exports[0].ResponseType)
}

func Test_EditExportRmLatencySampling(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", true)

	_, _, err := ExecuteCmd(createEditExportCmd(), "--subject", "a", "--sampling", "100", "--latency", "metrics.a")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac.Exports[0].Latency)

	_, _, err = ExecuteCmd(createEditExportCmd(), "--subject", "a", "--rm-latency-sampling")
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, ac.Exports[0].Latency)
}

func Test_EditExportNoExports(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditExportCmd(), "--subject", "a")
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have exports")
}
