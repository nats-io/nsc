/*
 * Copyright 2021 The NATS Authors
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

func Test_DeleteMapping(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createAddMappingCmd(), "--account", "A", "--from", "from1", "--to", "to1", "--weight", "50")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddMappingCmd(), "--account", "A", "--from", "from1", "--to", "to2", "--weight", "50")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddMappingCmd(), "--account", "A", "--from", "from2", "--to", "to1", "--weight", "50")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddMappingCmd(), "--account", "A", "--from", "from2", "--to", "to2", "--weight", "50")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Mappings, 2)
	require.Len(t, ac.Mappings["from1"], 2)
	require.Len(t, ac.Mappings["from2"], 2)

	// remove all mappings for from1
	_, _, err = ExecuteCmd(createDeleteMappingCmd(), "--account", "A", "--from", "from1")
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Mappings, 1)
	require.Len(t, ac.Mappings["from2"], 2)

	// remove particular mapping to1 from from2
	_, _, err = ExecuteCmd(createDeleteMappingCmd(), "--account", "A", "--from", "from2", "--to", "to1")
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Mappings, 1)
	require.Len(t, ac.Mappings["from2"], 1)

	// remove non existing mapping to3 from from2
	_, _, err = ExecuteCmd(createDeleteMappingCmd(), "--account", "A", "--from", "from2", "--to", "to3")
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Mappings, 1)
	require.Len(t, ac.Mappings["from2"], 1)

	// remove particular mapping to2 from from2
	_, _, err = ExecuteCmd(createDeleteMappingCmd(), "--account", "A", "--from", "from2", "--to", "to2")
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Mappings, 0)
}
