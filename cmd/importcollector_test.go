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

func Test_ImportCollectorBasics(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "A2")
	ts.AddExport(t, "A2", jwt.Service, "foo", true)
	ts.AddExport(t, "A2", jwt.Stream, "bar", false)
	ts.AddAccount(t, "A3")

	exports, err := GetAllExports()
	require.NoError(t, err)

	require.Len(t, exports, 1)
	ex := exports[0]
	require.Equal(t, "O", ex.OperatorName)
	require.Equal(t, "A2", ex.Name)
	require.Len(t, ex.Exports, 2)
}
