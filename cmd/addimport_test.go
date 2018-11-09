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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func TestAddImportFlags(t *testing.T) {
	s, dir, _ := CreateTestStore(t)

	pk, err := s.GetPublicKey()
	require.NoError(t, err)

	_, _, nk := CreateAccount(t)

	exports := CreateExport(true, "a", "b", "c")
	exports.Add(CreateExport(false, "a.>", "b.*", "a.*.b")...)
	activation := CreateActivation(t, pk, nk, exports...)

	tokenFile := filepath.Join(dir, "tokens.jwt")
	err = ioutil.WriteFile(tokenFile, []byte(activation), 0644)
	require.NoError(t, err)

	ac, err := jwt.DecodeActivationClaims(activation)
	require.NoError(t, err)
	jti := ac.ID

	_, _, err = ExecuteCmd(createLoadActivationCmd(), "--file", tokenFile)
	require.NoError(t, err)

	tests := CmdTests{
		{createAddImportCmd(), A("add", "import"), nil, A("required flag(s) \"jti\" not set"), true},
		{createAddImportCmd(), A("add", "import", "--jti", jti), nil, A("activation contains multiple exports specify --subject to select one or --all to import all"), true},
	}
	tests.Run(t, "root", "add")
}

//func TestGenerateAccount_Exports(t *testing.T) {
//	dir := MakeTempDir(t)
//	os.Setenv(store.NgsHomeEnv, dir)
//	InitStore(t)
//
//	_, _, err := ExecuteCmd(createAddExportCmd(), "--name", "tstream", "--stream", "foo.bar.>", "--tag", "stream")
//	require.NoError(t, err)
//	_, _, err = ExecuteCmd(createAddExportCmd(), "--name", "tservice", "--service", "barz", "--tag", "service")
//	require.NoError(t, err)
//
//	var exports Exports
//	require.NoError(t, exports.Load())
//	require.Len(t, exports, 2)
//
//	out, _, err := ExecuteCmd(createGenerateAccountCmd())
//	out = ExtractToken(out)
//
//	ac, err := jwt.DecodeAccountClaims(out)
//	require.NoError(t, err)
//
//	require.Len(t, ac.Exports, 2)
//}
