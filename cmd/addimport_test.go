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
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func Test_AddImport(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	kp, err := ts.KeyStore.GetAccountKey("B")
	require.NoError(t, err)
	require.NotNil(t, kp)
	d, err := kp.PublicKey()

	token := ts.GenerateActivation(t, string(d), "A", jwt.Stream, "foobar.>")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	tests := CmdTests{
		{createAddImportCmd(), []string{"add", "import"}, nil, []string{"an account is required"}, true},
		{createAddImportCmd(), []string{"add", "import", "--account", "B"}, nil, []string{"token is required"}, true},
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--token", fp}, nil, []string{"added stream import"}, false},
	}

	tests.Run(t, "root", "add")
}
