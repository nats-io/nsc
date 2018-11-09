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

func TestDeleteActivation(t *testing.T) {
	s, dir, _ := CreateTestStore(t)

	pk, err := s.GetPublicKey()
	require.NoError(t, err)

	exports := CreateExport(true, "a", "b", "c")
	token := CreateActivation(t, pk, nil, exports...)

	ac, err := jwt.DecodeActivationClaims(token)
	require.NoError(t, err)

	activationPath := filepath.Join(dir, "activation.jwt")
	err = Write(activationPath, []byte(token))
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createLoadActivationCmd(), "--file", activationPath)
	if err != nil {
		t.Fatal(err)
	}

	//c := CmdTest{createLoadActivationCmd(), []string{"import", "activation", "--file", activationPath}, nil, nil, false}
	//c.RunTest([]string{"root", "import"}, 1, t)

	tests := CmdTests{
		{createDeleteActivationCmd(), []string{"delete", "activation"}, nil, []string{"specify one of --jti or --interactive"}, true},
		{createDeleteActivationCmd(), []string{"delete", "activation", "--jti"}, nil, []string{"flag needs an argument: --jti"}, true},
		{createDeleteActivationCmd(), []string{"delete", "activation", "--jti", ac.ID}, nil, nil, false},
	}

	tests.Run(t, "root", "delete")
}
