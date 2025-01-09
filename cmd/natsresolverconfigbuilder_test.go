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
	"bytes"
	"fmt"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func Test_NatsResolverServerParse(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	_, err := ExecuteCmd(createAddOperatorCmd(), []string{"--name", "OP", "--sys"}...)
	require.NoError(t, err)
	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, err = ExecuteCmd(createServerConfigCmd(), []string{"--nats-resolver", "--config-file", serverconf}...)
	require.NoError(t, err)
	// modify the generated file so the jwt directory does not get created where the test is running
	data, err := os.ReadFile(serverconf)
	require.NoError(t, err)
	dir := ts.AddSubDir(t, "resolver")
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	err = os.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)
	// test parsing
	var opts server.Options
	require.NoError(t, opts.ProcessConfigFile(serverconf))
	require.NotEmpty(t, opts.SystemAccount)
	require.NotEmpty(t, opts.TrustedOperators)
}
