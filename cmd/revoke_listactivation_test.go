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
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func TestRevokeListActivation(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", false)
	ts.AddExport(t, "A", jwt.Service, "bar", false)
	ts.AddExport(t, "A", jwt.Service, "public", true) // we support revoking public exports

	_, pub, _ := CreateAccountKey(t)

	_, _, err := ExecuteCmd(createRevokeActivationCmd(), "--subject", "foo.bar", "--target-account", pub)
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createRevokeActivationCmd(), "--subject", "bar", "--target-account", pub, "--service", "--at", "1001")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createRevokeActivationCmd(), "--subject", "public", "--target-account", pub, "--service", "--at", "2001")
	require.NoError(t, err)

	stdout, _, err := ExecuteCmd(createRevokeListActivationCmd(), "--subject", "foo.bar")
	require.NoError(t, err)

	require.True(t, strings.Contains(stdout, pub))
	require.False(t, strings.Contains(stdout, time.Unix(1001, 0).Format(time.RFC1123)))
	require.False(t, strings.Contains(stdout, time.Unix(2001, 0).Format(time.RFC1123)))

	stdout, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--subject", "bar", "--service")
	require.NoError(t, err)

	require.True(t, strings.Contains(stdout, pub))
	require.True(t, strings.Contains(stdout, time.Unix(1001, 0).Format(time.RFC1123)))
	require.False(t, strings.Contains(stdout, time.Unix(2001, 0).Format(time.RFC1123)))

	stdout, _, err = ExecuteCmd(createRevokeListActivationCmd(), "--subject", "public", "--service")
	require.NoError(t, err)

	require.True(t, strings.Contains(stdout, pub))
	require.False(t, strings.Contains(stdout, time.Unix(1001, 0).Format(time.RFC1123)))
	require.True(t, strings.Contains(stdout, time.Unix(2001, 0).Format(time.RFC1123)))

}
