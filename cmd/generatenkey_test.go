// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_GenerateOperatorNKey(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	out, err := ExecuteCmd(createGenerateNKeyCmd(), "--operator")
	require.NoError(t, err)
	lines := strings.Split(out.Out, "\n")
	require.True(t, len(lines) >= 2)

	// seed
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, kp))
	_, err = kp.Seed()
	require.NoError(t, err)

	// pk
	pk, err := nkeys.FromPublicKey(lines[1])
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, pk))
	_, err = pk.Seed()
	require.Error(t, err)
}

func Test_GenerateNKeyAndStoreDoesntPrint(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	out, err := ExecuteCmd(createGenerateNKeyCmd(), "--operator", "--store")
	require.NoError(t, err)
	lines := strings.Split(out.Out, "\n")
	require.True(t, len(lines) == 4)
	require.Equal(t, lines[2], "")
	require.Equal(t, lines[3], "")

	// pk only
	pk := strings.TrimSpace(lines[0])
	kp, err := nkeys.FromPublicKey(pk)
	require.NoError(t, err)
	require.Equal(t, string(lines[0][0]), "O")
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, kp))
	require.NoError(t, err)

	// check this is the file
	chunks := strings.Split(lines[1], " ")
	fp := chunks[3]
	fp = strings.TrimSpace(fp)
	fp2 := ts.KeyStore.GetKeyPath(pk)
	require.Equal(t, fp, fp2)
}

func Test_GenerateNKeyAndStore(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	gpk, err := kp.PublicKey()
	require.NoError(t, err)
	gsk, err := kp.Seed()
	require.NoError(t, err)

	seed, err := ts.KeyStore.GetSeed(gpk)
	require.NoError(t, err)
	require.Equal(t, seed, string(gsk))

	// pk
	pk, err := ts.KeyStore.GetPublicKey(gpk)
	require.NoError(t, err)
	require.Equal(t, pk, gpk)
}

func Test_GenerateAccountNKey(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	out, err := ExecuteCmd(createGenerateNKeyCmd(), "--account")
	require.NoError(t, err)
	lines := strings.Split(out.Out, "\n")
	require.True(t, len(lines) >= 2)

	// seed
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteAccount, kp))
	_, err = kp.Seed()
	require.NoError(t, err)

	// pk
	pk, err := nkeys.FromPublicKey(lines[1])
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteAccount, pk))
	_, err = pk.Seed()
	require.Error(t, err)
}

func Test_GenerateUserNKey(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	out, err := ExecuteCmd(createGenerateNKeyCmd(), "--user")
	require.NoError(t, err)
	lines := strings.Split(out.Out, "\n")
	require.True(t, len(lines) >= 2)

	// seed
	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteUser, kp))
	_, err = kp.Seed()
	require.NoError(t, err)

	// pk
	pk, err := nkeys.FromPublicKey(lines[1])
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteUser, pk))
	_, err = pk.Seed()
	require.Error(t, err)
}

func Test_GenerateAllNKeys(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	out, err := ExecuteCmd(createGenerateNKeyCmd(), "--operator", "--account", "--user")
	require.NoError(t, err)
	lines := strings.Split(out.Out, "\n")
	require.True(t, len(lines) > 9)

	kp, err := nkeys.FromSeed([]byte(lines[0]))
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteOperator, kp))

	kp, err = nkeys.FromSeed([]byte(lines[3]))
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteAccount, kp))

	kp, err = nkeys.FromSeed([]byte(lines[6]))
	require.NoError(t, err)
	require.True(t, store.KeyPairTypeOk(nkeys.PrefixByteUser, kp))
}
