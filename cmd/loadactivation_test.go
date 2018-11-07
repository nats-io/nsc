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
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestLoadActivation(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)

	s := InitStore(t)

	pk, err := s.GetPublicKey()
	require.NoError(t, err)

	exports := CreateExport(true, "a", "b", "c")
	token := CreateActivation(t, pk, nil, exports...)

	notFoundPath := filepath.Join(dir, "notfound.jwt")

	activationPath := filepath.Join(dir, "activation.jwt")
	err = Write(activationPath, []byte(token))
	require.NoError(t, err)

	badJwt := filepath.Join(dir, "bad")
	err = Write(badJwt, []byte("helloworld"))
	require.NoError(t, err)

	tests := CmdTests{
		{createLoadActivationCmd(), []string{"load", "activation"}, nil, []string{"required flag(s) \"file\" not set"}, true},
		{createLoadActivationCmd(), []string{"load", "activation", "--file", notFoundPath}, nil, []string{"is not readable"}, true},
		{createLoadActivationCmd(), []string{"load", "activation", "--file", badJwt}, nil, []string{"error decoding activation"}, true},
		{createLoadActivationCmd(), []string{"load", "activation", "--file"}, nil, []string{"flag needs an argument: --file"}, true},
		{createLoadActivationCmd(), []string{"load", "activation", "--file", activationPath}, nil, []string{"Success! - loaded activation"}, false},
	}

	tests.Run(t, "root", "load")
}
