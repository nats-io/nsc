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
	"github.com/nats-io/nats-server/v2/server"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func Test_RttTool(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "SYS")

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oc.SystemAccount = ts.GetAccountPublicKey(t, "SYS")
	oc.OperatorServiceURLs.Add("nats://127.0.0.1:4222")
	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")

	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, err = ExecuteCmd(createServerConfigCmd(), []string{"--mem-resolver", "--config-file", serverconf}...)
	require.NoError(t, err)

	var opts server.Options
	require.NoError(t, opts.ProcessConfigFile(serverconf))

	s, err := server.NewServer(&opts)
	require.NoError(t, err)

	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("Unable to start NATS Server in Go Routine")
	}
	defer s.Shutdown()

	out, err := ExecuteCmd(createToolRTTCmd(), "--account", "A", "--user", "a")
	require.NoError(t, err)
	require.Contains(t, out.Out, "round trip time to [nats://127.0.0.1:4222]")
}
