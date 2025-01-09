// Copyright 2023-2025 The NATS Authors
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
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/v2/home"
	"github.com/stretchr/testify/require"
)

func Test_GenerateContext(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	old := home.SetTestConfigDir(ts.Dir)
	defer func() {
		home.SetTestConfigDir(old)
	}()

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, err := ExecuteCmd(createGenerateContext(), []string{"-a", "A", "-u", "U", "--context", "u"}...)
	require.NoError(t, err)

	fp := filepath.Join(ts.Dir, "nats", "context", "u.json")
	require.FileExists(t, fp)

	ctx := cliContext{}
	require.NoError(t, ReadJson(fp, &ctx))
	require.FileExists(t, ctx.Creds)
}
