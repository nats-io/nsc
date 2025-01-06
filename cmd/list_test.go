/*
 * Copyright 2025-2025 The NATS Authors
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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type entryJSON struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func Test_ListOperatorsJSON(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddOperator(t, "OO")

	cmd := createListOperatorsCmd()
	cmd.PersistentFlags().BoolVarP(&Json, "json", "J", false, "describe as JSON")

	out, err := ExecuteCmd(cmd, "--json")
	require.NoError(t, err)

	var entries []entryJSON
	require.NoError(t, json.Unmarshal([]byte(out.Out), &entries))
	assert.Len(t, entries, 2)
	assert.Equal(t, entries[0].Name, "O")
	assert.NotEmpty(t, entries[0].PublicKey)
	assert.Equal(t, entries[1].Name, "OO")
	assert.NotEmpty(t, entries[1].PublicKey)
}

func Test_ListAccountsJSON(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	cmd := createListAccountsCmd()
	cmd.PersistentFlags().BoolVarP(&Json, "json", "J", false, "describe as JSON")

	out, err := ExecuteCmd(cmd, "--json")
	require.NoError(t, err)

	var entries []entryJSON
	require.NoError(t, json.Unmarshal([]byte(out.Out), &entries))
	assert.Len(t, entries, 2)
	assert.Equal(t, entries[0].Name, "A")
	assert.Equal(t, entries[0].PublicKey, ts.GetAccountPublicKey(t, "A"))
	assert.Equal(t, entries[1].Name, "B")
	assert.Equal(t, entries[1].PublicKey, ts.GetAccountPublicKey(t, "B"))
}

func Test_ListUsersJSON(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	ts.AddUser(t, "A", "UU")

	cmd := createListUsersCmd()
	cmd.PersistentFlags().BoolVarP(&Json, "json", "J", false, "describe as JSON")

	out, err := ExecuteCmd(cmd, "--json")
	require.NoError(t, err)

	var entries []entryJSON
	require.NoError(t, json.Unmarshal([]byte(out.Out), &entries))
	assert.Len(t, entries, 2)
	assert.Equal(t, entries[0].Name, "U")
	assert.Equal(t, entries[0].PublicKey, ts.GetUserPublicKey(t, "A", "U"))
	assert.Equal(t, entries[1].Name, "UU")
	assert.Equal(t, entries[1].PublicKey, ts.GetUserPublicKey(t, "A", "UU"))
}
