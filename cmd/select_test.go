/*
 * Copyright 2018-2022 The NATS Authors
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

func TestSelectAccount(t *testing.T) {
	require := require.New(t)
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(selectAccountCmd(), "A")
	require.NotNil(err)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, _, err = ExecuteCmd(selectAccountCmd(), "A")
	require.Nil(err)
	conf := GetConfig()
	require.Equal(conf.Account, "A")

	_, _, err = ExecuteCmd(selectAccountCmd(), "B")
	require.Nil(err)
	conf = GetConfig()
	require.Equal(conf.Account, "B")

	_, _, err = ExecuteCmd(selectAccountCmd(), "NO")
	require.NotNil(err)
	require.Contains(err.Error(), "\"NO\" not in accounts for operator")

	conf = GetConfig()
	require.Equal(conf.Account, "B")
}

func TestSelectOperator(t *testing.T) {
	require := require.New(t)
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(selectOperatorCmd(), "test")
	require.Nil(err)

	ts.AddOperator(t, "test2")
	ts.AddOperator(t, "test3")

	_, _, err = ExecuteCmd(selectOperatorCmd(), "test2")
	require.Nil(err)
	conf := GetConfig()
	require.Equal(conf.Operator, "test2")

	_, _, err = ExecuteCmd(selectOperatorCmd(), "test3")
	require.Nil(err)
	conf = GetConfig()
	require.Equal(conf.Operator, "test3")

	_, _, err = ExecuteCmd(selectOperatorCmd(), "NO")
	require.NotNil(err)
	require.Contains(err.Error(), "operator \"NO\" not in")

	conf = GetConfig()
	require.Equal(conf.Operator, "test3")
}
