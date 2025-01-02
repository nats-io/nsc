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

	_, stderr, err := ExecuteCmd(cmd, "--json")
	require.NoError(t, err)

	var entries []entryJSON
	require.NoError(t, json.Unmarshal([]byte(stderr), &entries))
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

	_, stderr, err := ExecuteCmd(cmd, "--json")
	require.NoError(t, err)

	var entries []entryJSON
	require.NoError(t, json.Unmarshal([]byte(stderr), &entries))
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

	_, stderr, err := ExecuteCmd(cmd, "--json")
	require.NoError(t, err)

	var entries []entryJSON
	require.NoError(t, json.Unmarshal([]byte(stderr), &entries))
	assert.Len(t, entries, 2)
	assert.Equal(t, entries[0].Name, "U")
	assert.Equal(t, entries[0].PublicKey, ts.GetUserPublicKey(t, "A", "U"))
	assert.Equal(t, entries[1].Name, "UU")
	assert.Equal(t, entries[1].PublicKey, ts.GetUserPublicKey(t, "A", "UU"))
}
