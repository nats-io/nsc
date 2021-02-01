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

	"github.com/stretchr/testify/require"
)

func Test_ListWellKnownOperators(t *testing.T) {
	wko, err := GetWellKnownOperators()
	require.NoError(t, err)
	require.NotNil(t, wko)
	require.True(t, len(wko) >= 1)

	s, err := FindKnownOperator("SYNADIA")
	require.NoError(t, err)
	require.NotNil(t, s)

	s, err = FindKnownOperator("local")
	require.NoError(t, err)
	require.Nil(t, s)
}

func Test_FindEnvOperators(t *testing.T) {
	env := []string{
		"one=1",
		"nsc_opa_operator=http://localhost:1234",
		"NSC_opb_operator=http://localhost:5678",
		"NSC_HOME=x",
	}

	ops := findEnvOperators(env)
	require.Len(t, ops, 2)
	require.Equal(t, "opa", ops[0].Name)
	require.Equal(t, "http://localhost:1234", ops[0].AccountServerURL)
	require.Equal(t, "opb", ops[1].Name)
	require.Equal(t, "http://localhost:5678", ops[1].AccountServerURL)
}

func Test_GetOperatorName(t *testing.T) {
	wko, err := GetWellKnownOperators()
	require.NoError(t, err)
	require.NotNil(t, wko)
	require.True(t, len(wko) >= 1)

	n := GetOperatorName("test", "https://api.synadia.io/jwt/v2/synadia")
	require.Equal(t, "synadia", n)

	n = GetOperatorName("X", "http://something.io/jwt/v1/foobar")
	require.Equal(t, "X", n)
}
