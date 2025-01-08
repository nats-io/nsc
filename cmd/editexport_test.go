/*
 * Copyright 2018-2025 The NATS Authors
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
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_EditExport_Private(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", 0, true)

	_, err := ExecuteCmd(createEditExportCmd(), []string{"--subject", "a", "--private", "--response-type", jwt.ResponseTypeChunked}...)
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
	ts.AddExport(t, "A", jwt.Service, "a", 0, true)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, ac.Exports[0].Latency)

	_, err = ExecuteCmd(createEditExportCmd(), []string{"--subject", "a", "--sampling", "100", "--latency", "lat", "--response-threshold", "1s"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, jwt.SamplingRate(100), ac.Exports[0].Latency.Sampling)
	require.Equal(t, jwt.Subject("lat"), ac.Exports[0].Latency.Results)
	require.Equal(t, time.Second, ac.Exports[0].ResponseThreshold)
}

func Test_EditExportInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", 0, true)
	ts.AddExport(t, "A", jwt.Service, "b", 0, true)

	link := "http://foo/bar"
	_, err := ExecuteInteractiveCmd(createEditExportCmd(), []interface{}{1, 1, "c", "c", false, false, 1, "1s", "desc", link})
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 2)
	require.Equal(t, jwt.Subject("c"), ac.Exports[1].Subject)
	require.EqualValues(t, jwt.ResponseTypeStream, ac.Exports[1].ResponseType)
	require.Equal(t, ac.Exports[1].Description, "desc")
	require.Equal(t, ac.Exports[1].InfoURL, link)
	require.Equal(t, ac.Exports[1].ResponseThreshold, time.Second)
}

func Test_EditExportInteractiveLatency(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", 0, true)

	_, err := ExecuteInteractiveCmd(createEditExportCmd(), []interface{}{0, 1, "c", "c", false, true, "header", "lat", 2, "", "", ""})
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, jwt.Subject("c"), ac.Exports[0].Subject)
	require.Equal(t, "c", ac.Exports[0].Name)
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, jwt.Headers, ac.Exports[0].Latency.Sampling)
	require.Equal(t, jwt.Subject("lat"), ac.Exports[0].Latency.Results)
	require.EqualValues(t, jwt.ResponseTypeChunked, ac.Exports[0].ResponseType)
}

func Test_EditExportRmLatencySampling(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "a", 0, true)

	_, err := ExecuteCmd(createEditExportCmd(), []string{"--subject", "a", "--sampling", "header", "--latency", "metrics.a"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac.Exports[0].Latency)
	require.Equal(t, jwt.Headers, ac.Exports[0].Latency.Sampling)

	_, err = ExecuteCmd(createEditExportCmd(), []string{"--subject", "a", "--rm-latency-sampling"}...)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, ac.Exports[0].Latency)
}

func Test_EditExportNoExports(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditExportCmd(), []string{"--subject", "a"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "doesn't have exports")
}

func TestEditServiceExportWTracing(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createAddExportCmd(), []string{"--service", "--subject", "q", "--allow-trace"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, ac.Exports[0].AllowTrace)

	_, err = ExecuteCmd(createEditExportCmd(), []string{"--service", "--subject", "q", "--allow-trace=false"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.False(t, ac.Exports[0].AllowTrace)
}

func TestEditStreamExportWTracing(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createAddExportCmd(), []string{"--subject", "q"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditExportCmd(), []string{"--subject", "q", "--allow-trace"}...)
	require.Error(t, err)
}
