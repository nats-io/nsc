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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteUserCmd(t *testing.T) {
	_, _, _ = CreateTestStore(t)

	_, pk, _ := CreateUser(t)

	_, _, err := ExecuteCmd(createAddUserCmd(), "--public-key", pk)
	require.NoError(t, err)

	tests := CmdTests{
		{createDeleteUserCmd(), []string{"delete", "user"}, nil, []string{"error specify one of --public-key or --interactive to the user to delete"}, true},
		{createDeleteUserCmd(), []string{"delete", "user", "--public-key"}, nil, []string{"flag needs an argument: --public-key"}, true},
		{createDeleteUserCmd(), []string{"delete", "user", "--public-key", pk}, nil, nil, false},
		{createDeleteUserCmd(), []string{"delete", "user", "--public-key", "notfound"}, nil, []string{"notfound.user: no such file or directory"}, true},
	}
	tests.Run(t, "root", "delete")
}
