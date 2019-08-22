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
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_GenerateOperatorNKey(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, stderr, err := ExecuteCmd(createGenerateNKeyCmd(), "--operator")
	require.NoError(t, err)
	lines := strings.Split(stderr, "\n")
	require.True(t, len(lines) >= 2)

	// seed
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, kp))
	_, err = kp.Seed()
	require.NoError(t, err)

	// pk
	pk, err := nkeys.FromPublicKey(lines[1])
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, pk))
	_, err = pk.Seed()
	require.Error(t, err)
}

func Test_GenerateNKeyAndStore(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, stderr, err := ExecuteCmd(createGenerateNKeyCmd(), "--operator", "--store")
	require.NoError(t, err)
	lines := strings.Split(stderr, "\n")
	require.True(t, len(lines) >= 2)

	seed, err := ts.KeyStore.GetSeed(lines[1])
	require.NoError(t, err)
	require.Equal(t, lines[0], seed)

	// pk
	pk, err := ts.KeyStore.GetPublicKey(lines[1])
	require.NoError(t, err)
	require.Equal(t, lines[1], pk)
}

func Test_GenerateAccountNKey(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, stderr, err := ExecuteCmd(createGenerateNKeyCmd(), "--account")
	require.NoError(t, err)
	lines := strings.Split(stderr, "\n")
	require.True(t, len(lines) >= 2)

	// seed
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteAccount, kp))
	_, err = kp.Seed()
	require.NoError(t, err)

	// pk
	pk, err := nkeys.FromPublicKey(lines[1])
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteAccount, pk))
	_, err = pk.Seed()
	require.Error(t, err)
}

func Test_GenerateUserNKey(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, stderr, err := ExecuteCmd(createGenerateNKeyCmd(), "--user")
	require.NoError(t, err)
	lines := strings.Split(stderr, "\n")
	require.True(t, len(lines) >= 2)

	// seed
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteUser, kp))
	_, err = kp.Seed()
	require.NoError(t, err)

	// pk
	pk, err := nkeys.FromPublicKey(lines[1])
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteUser, pk))
	_, err = pk.Seed()
	require.Error(t, err)
}

func Test_GenerateAllNKeys(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, stderr, err := ExecuteCmd(createGenerateNKeyCmd(), "--operator", "--account", "--user")
	require.NoError(t, err)
	t.Log(stderr)
	lines := strings.Split(stderr, "\n")
	require.True(t, len(lines) > 9)

	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, kp))

	kp, err = nkeys.FromSeed([]byte(lines[3]))
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteAccount, kp))

	kp, err = nkeys.FromSeed([]byte(lines[6]))
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteUser, kp))
}
