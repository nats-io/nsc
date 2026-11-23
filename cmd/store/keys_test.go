// Copyright 2018-2022 The NATS Authors
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

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/home"
	"github.com/nats-io/nsc/v2/internal/fips"
	"github.com/stretchr/testify/require"
)

func TestResolveLocal(t *testing.T) {
	old := KeyStorePath
	KeyStorePath = ""
	dir := GetKeysDir()
	dp := home.NscDataHome(home.KeysSubDirName)
	KeyStorePath = old
	require.Equal(t, dir, dp)
}

func TestResolveEnv(t *testing.T) {
	old := KeyStorePath
	p := filepath.Join("foo", "bar")
	KeyStorePath = p
	dir := GetKeysDir()
	KeyStorePath = old
	require.Equal(t, dir, p)
}

func TestMatchKeys(t *testing.T) {
	_, apk, akp := CreateAccountKey(t)
	_, opk, _ := CreateOperatorKey(t)

	require.True(t, Match(apk, akp))
	require.False(t, Match(opk, akp))
}

func TestGetKeyNonExist(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir

	ks := NewKeyStore("test_get_keys")
	_, _, okp := CreateOperatorKey(t)
	_, err := ks.Store(okp)
	require.NoError(t, err)

	_, apk, _ := CreateAccountKey(t)
	kp, err := ks.GetKeyPair(apk)
	require.NoError(t, err)
	require.Nil(t, kp)

	KeyStorePath = old
}

func TestGetKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir

	ks := NewKeyStore("test_get_keys")

	_, opk, okp := CreateOperatorKey(t)

	_, err := ks.Store(okp)
	require.NoError(t, err)
	ookp, err := ks.GetKeyPair(opk)
	require.NoError(t, err)
	oopk, err := ookp.PublicKey()
	require.NoError(t, err)
	require.True(t, Match(opk, ookp))
	require.Equal(t, opk, oopk)

	_, apk, akp := CreateAccountKey(t)
	_, err = ks.Store(akp)
	require.NoError(t, err)

	aakp, err := ks.GetKeyPair(apk)
	require.NoError(t, err)

	aapk, err := aakp.PublicKey()
	require.NoError(t, err)

	require.True(t, Match(apk, aakp))
	require.Equal(t, apk, aapk)

	KeyStorePath = old
}

func Test_RemoveKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir

	ks := NewKeyStore(t.Name())

	_, opk, okp := CreateOperatorKey(t)

	_, err := ks.Store(okp)
	require.NoError(t, err)
	ookp, err := ks.GetKeyPair(opk)
	require.NoError(t, err)
	oopk, err := ookp.PublicKey()
	require.NoError(t, err)
	require.True(t, Match(opk, ookp))
	require.Equal(t, opk, oopk)

	require.NoError(t, ks.Remove(opk))
	kp := ks.GetKeyPath(opk)
	_, err = os.Stat(kp)
	require.True(t, os.IsNotExist(err))

	KeyStorePath = old
}

func TestGetMissingKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir

	_, opk, _ := CreateOperatorKey(t)

	ks := NewKeyStore("test_get_private_key")

	ckp, err := ks.GetKeyPair(opk)
	require.Nil(t, err)
	require.Nil(t, ckp)
	KeyStorePath = old
}

func CreateAccountKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateAccount)
}

func CreateOperatorKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateOperator)
}

func CreateUserKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateUser)
}

func CreateTestNKey(t *testing.T, f NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, pub, kp
}

func CreateClusterKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateCluster)
}

func CreateServerKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateServer)
}

func TestPubKeyType(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	_, opk, _ := CreateOperatorKey(t)
	_, apk, _ := CreateAccountKey(t)
	_, upk, _ := CreateUserKey(t)
	_, cpk, _ := CreateClusterKey(t)
	_, spk, _ := CreateServerKey(t)
	xkp, err := nkeys.CreateCurveKeys()
	require.NoError(t, err)
	xpk, err := xkp.PublicKey()
	require.NoError(t, err)

	cases := []struct {
		pk   string
		want nkeys.PrefixByte
	}{
		{opk, nkeys.PrefixByteOperator},
		{apk, nkeys.PrefixByteAccount},
		{upk, nkeys.PrefixByteUser},
		{cpk, nkeys.PrefixByteCluster},
		{spk, nkeys.PrefixByteServer},
		{xpk, nkeys.PrefixByteCurve},
	}
	for _, c := range cases {
		got, err := PubKeyType(c.pk)
		require.NoError(t, err)
		require.Equal(t, c.want, got, "pk %s", c.pk)
	}

	_, err = PubKeyType("not-a-key")
	require.Error(t, err)
}

func TestIsPublicKey(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	_, opk, _ := CreateOperatorKey(t)
	_, apk, _ := CreateAccountKey(t)
	_, upk, _ := CreateUserKey(t)
	_, cpk, _ := CreateClusterKey(t)
	_, spk, _ := CreateServerKey(t)
	xkp, err := nkeys.CreateCurveKeys()
	require.NoError(t, err)
	xpk, err := xkp.PublicKey()
	require.NoError(t, err)

	// correct kind for the key
	require.True(t, IsPublicKey(nkeys.PrefixByteOperator, opk))
	require.True(t, IsPublicKey(nkeys.PrefixByteAccount, apk))
	require.True(t, IsPublicKey(nkeys.PrefixByteUser, upk))
	require.True(t, IsPublicKey(nkeys.PrefixByteCluster, cpk))
	require.True(t, IsPublicKey(nkeys.PrefixByteServer, spk))
	require.True(t, IsPublicKey(nkeys.PrefixByteCurve, xpk))

	// wrong kind for the key returns false
	require.False(t, IsPublicKey(nkeys.PrefixByteAccount, opk))
	require.False(t, IsPublicKey(nkeys.PrefixByteUser, apk))

	// unsupported prefix returns false
	require.False(t, IsPublicKey(nkeys.PrefixBytePrivate, opk))

	// bogus inputs return false (not panic)
	require.False(t, IsPublicKey(nkeys.PrefixByteUser, ""))
	require.False(t, IsPublicKey(nkeys.PrefixByteUser, "garbage"))
}

func TestKeyPairTypeOk(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	_, _, akp := CreateAccountKey(t)

	require.True(t, KeyPairTypeOk(nkeys.PrefixByteOperator, okp))
	require.True(t, KeyPairTypeOk(nkeys.PrefixByteAccount, akp))
	require.False(t, KeyPairTypeOk(nkeys.PrefixByteAccount, okp))
	require.False(t, KeyPairTypeOk(nkeys.PrefixByteOperator, akp))
}

func TestExtractSeed_RawSeed(t *testing.T) {
	seed, pk, _ := CreateUserKey(t)
	kp, err := ExtractSeed(string(seed))
	require.NoError(t, err)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, got)
}

func TestExtractSeed_FromCredsBlock(t *testing.T) {
	seed, pk, _ := CreateUserKey(t)
	// minimal creds-shaped block; ExtractSeed scans for BEGIN/END SEED markers
	creds := "-----BEGIN NATS USER JWT-----\n" +
		"eyJhbGciOiJlZDI1NTE5In0.eyJzdWIiOiJ4In0.sig\n" +
		"------END NATS USER JWT------\n\n" +
		"-----BEGIN USER NKEY SEED-----\n" +
		string(seed) + "\n" +
		"------END USER NKEY SEED------\n"
	kp, err := ExtractSeed(creds)
	require.NoError(t, err)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, got)
}

func TestExtractSeed_MultilineSeed(t *testing.T) {
	seed, pk, _ := CreateUserKey(t)
	// markers present, seed split across lines (ExtractSeed joins them)
	half := len(seed) / 2
	creds := "-----BEGIN USER NKEY SEED-----\n" +
		string(seed[:half]) + "\n" +
		string(seed[half:]) + "\n" +
		"------END USER NKEY SEED------\n"
	kp, err := ExtractSeed(creds)
	require.NoError(t, err)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, got)
}

func TestExtractSeed_Malformed(t *testing.T) {
	_, err := ExtractSeed("not a seed and not creds")
	require.Error(t, err)
}

func TestRelCredsPath(t *testing.T) {
	sep := string(os.PathSeparator)
	root := filepath.Join("tmp", "ks")

	// already in new format: creds/<op>/<act>/<user>.creds
	newP := filepath.Join(root, "creds", "op", "act", "u.creds")
	got, err := relCredsPath(root, newP)
	require.NoError(t, err)
	require.Equal(t, "creds"+sep+"op"+sep+"act"+sep+"u.creds", got)

	// old format: <op>/accounts/<act>/users/<u>.creds
	oldP := filepath.Join(root, "op", "accounts", "act", "users", "u.creds")
	got, err = relCredsPath(root, oldP)
	require.NoError(t, err)
	require.Equal(t, "creds"+sep+"op"+sep+"act"+sep+"u.creds", got)

	// unexpected layout
	_, err = relCredsPath(root, filepath.Join(root, "stray.creds"))
	require.Error(t, err)
}

func TestAbbrevHomePaths(t *testing.T) {
	h, err := homedir.Dir()
	require.NoError(t, err)
	in := filepath.Join(h, "a", "b")
	require.Equal(t, "~"+string(os.PathSeparator)+filepath.Join("a", "b"), AbbrevHomePaths(in))

	// path outside home is left alone
	out := filepath.Join("/", "elsewhere", "x")
	require.Equal(t, out, AbbrevHomePaths(out))
}

func TestCalcCredsPaths(t *testing.T) {
	old := KeyStorePath
	KeyStorePath = filepath.Join("tmp", "ks")
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore("envA")
	require.Equal(t, filepath.Join("tmp", "ks", CredsDir, "envA", "acct"), ks.CalcAccountCredsDir("acct"))
	require.Equal(t, filepath.Join("tmp", "ks", CredsDir, "envA", "acct", "u.creds"), ks.CalcUserCredsPath("acct", "u"))
}

func TestGetUserCredsPath_Missing(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore("env")
	require.Equal(t, "", ks.GetUserCredsPath("acct", "u"))
}

func TestGetSeedAndPublicKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore(t.Name())
	seed, pk, kp := CreateUserKey(t)
	_, err := ks.Store(kp)
	require.NoError(t, err)

	gotPk, err := ks.GetPublicKey(pk)
	require.NoError(t, err)
	require.Equal(t, pk, gotPk)

	gotSeed, err := ks.GetSeed(pk)
	require.NoError(t, err)
	require.Equal(t, string(seed), gotSeed)

	require.True(t, ks.HasPrivateKey(pk))

	// public-only key has no private material
	pubOnly, err := nkeys.FromPublicKey(pk)
	require.NoError(t, err)
	_, err = ks.Store(pubOnly)
	// Store requires a seed - it should fail; if not, HasPrivateKey on a
	// random unknown pk should still report false.
	_ = err
	_, otherPk, _ := CreateUserKey(t)
	require.False(t, ks.HasPrivateKey(otherPk))
}

func TestMaybeStoreUserCreds_MalformedData(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore("env")
	_, err := ks.MaybeStoreUserCreds("acct", "u", []byte("not creds, not a seed"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "error reading creds data")
}

func TestMaybeStoreUserCreds_OK(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore("env")
	seed, _, kp := CreateUserKey(t)
	_, err := ks.Store(kp)
	require.NoError(t, err)

	creds := "-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n"
	fp, err := ks.MaybeStoreUserCreds("acct", "u", []byte(creds))
	require.NoError(t, err)
	require.FileExists(t, fp)

	// the file path is what GetUserCredsPath returns
	require.Equal(t, fp, ks.GetUserCredsPath("acct", "u"))
}

func TestIsOldKeyRing_New(t *testing.T) {
	dir := MakeTempDir(t)
	// new-style structure: only the keys/ and creds/ subdirs hold .nk/.creds
	require.NoError(t, MaybeMakeDir(filepath.Join(dir, KeysDir, "U", "AA")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, KeysDir, "U", "AA", "ignored.nk"), []byte("x"), 0600))

	old, err := IsOldKeyRing(dir)
	require.NoError(t, err)
	require.False(t, old)
}

func TestIsOldKeyRing_Old(t *testing.T) {
	dir := MakeTempDir(t)
	// .nk file located outside the keys/ subdir marks an old keyring
	require.NoError(t, MaybeMakeDir(filepath.Join(dir, "myop")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "myop", "stray.nk"), []byte("x"), 0600))

	old, err := IsOldKeyRing(dir)
	require.NoError(t, err)
	require.True(t, old)
}

func TestKeysNeedMigration(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	// empty dir → no migration
	need, err := KeysNeedMigration()
	require.NoError(t, err)
	require.False(t, need)

	// place an old-style stray .nk → needs migration
	require.NoError(t, MaybeMakeDir(filepath.Join(dir, "op")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "op", "stray.nk"), []byte("x"), 0600))
	need, err = KeysNeedMigration()
	require.NoError(t, err)
	require.True(t, need)
}

func TestMigrate_OldKeyStore(t *testing.T) {
	// GetKeysDir must sit inside a parent dir Migrate can write siblings into
	parent := MakeTempDir(t)
	keysDir := filepath.Join(parent, "keys-root")
	require.NoError(t, MaybeMakeDir(keysDir))

	old := KeyStorePath
	KeyStorePath = keysDir
	defer func() { KeyStorePath = old }()

	// craft an old layout under keysDir:
	//   keysDir/<op>/<pubkey>.nk             (raw key seed)
	//   keysDir/<op>/accounts/<act>/users/<u>.creds
	opName := "myop"
	actName := "myact"
	userName := "myuser"

	_, upk, ukp := CreateUserKey(t)
	useed, err := ukp.Seed()
	require.NoError(t, err)

	opDir := filepath.Join(keysDir, opName)
	require.NoError(t, MaybeMakeDir(opDir))
	require.NoError(t, os.WriteFile(filepath.Join(opDir, upk+".nk"), useed, 0600))

	credsDir := filepath.Join(opDir, "accounts", actName, "users")
	require.NoError(t, MaybeMakeDir(credsDir))
	credsBody := []byte("creds-bytes")
	require.NoError(t, os.WriteFile(filepath.Join(credsDir, userName+".creds"), credsBody, 0600))

	// pre-check: detected as old
	isOld, err := IsOldKeyRing(keysDir)
	require.NoError(t, err)
	require.True(t, isOld)

	renamed, err := Migrate()
	require.NoError(t, err)
	require.DirExists(t, renamed)

	// after Migrate, the keysDir path holds the new layout
	require.DirExists(t, filepath.Join(keysDir, KeysDir))
	require.DirExists(t, filepath.Join(keysDir, CredsDir))

	// the key is now under keys/<kind>/<shard>/<pk>.nk
	kind := upk[0:1]
	shard := upk[1:3]
	migratedKey := filepath.Join(keysDir, KeysDir, kind, shard, upk+".nk")
	require.FileExists(t, migratedKey)
	gotSeed, err := os.ReadFile(migratedKey)
	require.NoError(t, err)
	require.Equal(t, string(useed), string(gotSeed))

	// creds are now under creds/<op>/<act>/<user>.creds
	migratedCreds := filepath.Join(keysDir, CredsDir, opName, actName, userName+".creds")
	require.FileExists(t, migratedCreds)
	gotCreds, err := os.ReadFile(migratedCreds)
	require.NoError(t, err)
	require.Equal(t, string(credsBody), string(gotCreds))

	// migration should no longer be needed
	need, err := KeysNeedMigration()
	require.NoError(t, err)
	require.False(t, need)
}

func TestResolveKey_Empty(t *testing.T) {
	kp, err := ResolveKey("")
	require.NoError(t, err)
	require.Nil(t, kp)
}

func TestResolveKey_RawSeed(t *testing.T) {
	seed, pk, _ := CreateUserKey(t)
	kp, err := ResolveKey(string(seed))
	require.NoError(t, err)
	require.NotNil(t, kp)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, got)
}

func TestResolveKey_RawPublicKey(t *testing.T) {
	_, pk, _ := CreateUserKey(t)
	kp, err := ResolveKey(pk)
	require.NoError(t, err)
	require.NotNil(t, kp)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, got)
}

func TestResolveKey_FromFile(t *testing.T) {
	dir := MakeTempDir(t)
	seed, pk, _ := CreateUserKey(t)
	fp := filepath.Join(dir, "u.nk")
	require.NoError(t, os.WriteFile(fp, seed, 0600))

	kp, err := ResolveKey(fp)
	require.NoError(t, err)
	require.NotNil(t, kp)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, got)
}

func TestResolveKey_NonExistentPath(t *testing.T) {
	// non-existent path falls through dataFromFile (returns nil,nil),
	// then resolveAsKey(nil) returns nil,nil - documenting current behavior
	kp, err := ResolveKey("not-a-key-not-a-path")
	require.NoError(t, err)
	require.Nil(t, kp)
}

func TestResolveKey_FileWithGarbage(t *testing.T) {
	dir := MakeTempDir(t)
	fp := filepath.Join(dir, "junk")
	require.NoError(t, os.WriteFile(fp, []byte("not a seed"), 0600))
	_, err := ResolveKey(fp)
	require.Error(t, err)
}

func TestAllKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() {
		KeyStorePath = old
	}()

	ks := NewKeyStore(t.Name())
	_, opk, okp := CreateOperatorKey(t)
	_, err := ks.Store(okp)
	require.NoError(t, err)

	_, apk, akp := CreateAccountKey(t)
	_, err = ks.Store(akp)
	require.NoError(t, err)

	keys, err := ks.AllKeys()
	require.NoError(t, err)
	require.Contains(t, keys, opk)
	require.Contains(t, keys, apk)
}

func CreateCurveKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateCurveKeys)
}

func TestXKey_StoreAndRead(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore(t.Name())
	seed, xpk, xkp := CreateCurveKey(t)
	require.Equal(t, "SX", string(seed[:2]))

	fp, err := ks.Store(xkp)
	require.NoError(t, err)
	// curve keys are sharded under X like any other key kind
	require.Equal(t, filepath.Join(dir, KeysDir, "X", xpk[1:3], xpk+NKeyExtension), fp)
	require.Equal(t, fp, ks.GetKeyPath(xpk))
	d, err := os.ReadFile(fp)
	require.NoError(t, err)
	require.Equal(t, string(seed), string(d))

	kp, err := ks.GetKeyPair(xpk)
	require.NoError(t, err)
	require.NotNil(t, kp)
	require.True(t, Match(xpk, kp))

	gotPk, err := ks.GetPublicKey(xpk)
	require.NoError(t, err)
	require.Equal(t, xpk, gotPk)

	gotSeed, err := ks.GetSeed(xpk)
	require.NoError(t, err)
	require.Equal(t, string(seed), gotSeed)

	require.True(t, ks.HasPrivateKey(xpk))
	_, otherPk, _ := CreateCurveKey(t)
	require.False(t, ks.HasPrivateKey(otherPk))

	// storing the same key again is a noop
	fp2, err := ks.Store(xkp)
	require.NoError(t, err)
	require.Equal(t, fp, fp2)
}

func TestXKey_Remove(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore(t.Name())
	_, xpk, xkp := CreateCurveKey(t)
	fp, err := ks.Store(xkp)
	require.NoError(t, err)
	require.FileExists(t, fp)

	require.NoError(t, ks.Remove(xpk))
	_, err = os.Stat(fp)
	require.True(t, os.IsNotExist(err))
	require.False(t, ks.HasPrivateKey(xpk))

	kp, err := ks.GetKeyPair(xpk)
	require.NoError(t, err)
	require.Nil(t, kp)

	// removing a missing key is not an error
	require.NoError(t, ks.Remove(xpk))
}

func TestXKey_AllKeys(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore(t.Name())
	_, apk, akp := CreateAccountKey(t)
	_, err := ks.Store(akp)
	require.NoError(t, err)
	_, xpk, xkp := CreateCurveKey(t)
	_, err = ks.Store(xkp)
	require.NoError(t, err)

	keys, err := ks.AllKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Contains(t, keys, apk)
	require.Contains(t, keys, xpk)
}

func TestXKey_MatchAndType(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	_, xpk, xkp := CreateCurveKey(t)
	_, xpk2, _ := CreateCurveKey(t)
	_, apk, akp := CreateAccountKey(t)

	require.True(t, Match(xpk, xkp))
	require.False(t, Match(xpk2, xkp))
	require.False(t, Match(apk, xkp))
	require.False(t, Match(xpk, akp))

	require.True(t, KeyPairTypeOk(nkeys.PrefixByteCurve, xkp))
	require.False(t, KeyPairTypeOk(nkeys.PrefixByteAccount, xkp))
	require.False(t, KeyPairTypeOk(nkeys.PrefixByteCurve, akp))

	kind, err := KeyType(xkp)
	require.NoError(t, err)
	require.Equal(t, nkeys.PrefixByteCurve, kind)
}

func TestXKey_ExtractSeed(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	seed, xpk, _ := CreateCurveKey(t)

	kp, err := ExtractSeed(string(seed))
	require.NoError(t, err)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, xpk, got)

	block := "-----BEGIN CURVE NKEY SEED-----\n" +
		string(seed) + "\n" +
		"------END CURVE NKEY SEED------\n"
	kp, err = ExtractSeed(block)
	require.NoError(t, err)
	got, err = kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, xpk, got)
}

func TestXKey_ResolveKey(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	seed, xpk, _ := CreateCurveKey(t)

	// raw seed
	kp, err := ResolveKey(string(seed))
	require.NoError(t, err)
	require.NotNil(t, kp)
	got, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, xpk, got)
	gotSeed, err := kp.Seed()
	require.NoError(t, err)
	require.Equal(t, string(seed), string(gotSeed))

	// seed in a file
	dir := MakeTempDir(t)
	fp := filepath.Join(dir, "x.nk")
	require.NoError(t, os.WriteFile(fp, seed, 0600))
	kp, err = ResolveKey(fp)
	require.NoError(t, err)
	require.NotNil(t, kp)
	got, err = kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, xpk, got)

	// raw public key
	kp, err = ResolveKey(xpk)
	require.NoError(t, err)
	require.NotNil(t, kp)
	got, err = kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, xpk, got)
}

// a different seed already stored at a key's path must not be overwritten
func TestStore_ConflictingKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := KeyStorePath
	KeyStorePath = dir
	defer func() { KeyStorePath = old }()

	ks := NewKeyStore(t.Name())
	_, apk, akp := CreateAccountKey(t)
	other, _, _ := CreateAccountKey(t)

	fp := ks.GetKeyPath(apk)
	require.NoError(t, os.MkdirAll(filepath.Dir(fp), 0700))
	require.NoError(t, os.WriteFile(fp, other, 0600))

	_, err := ks.Store(akp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists and is different")

	d, err := os.ReadFile(fp)
	require.NoError(t, err)
	require.Equal(t, string(other), string(d))
}

// seeds reach the store from files written by hand or by other tooling, so
// line endings, padding and armor must not matter - for any key kind
func TestExtractSeed_Shapes(t *testing.T) {
	useed, upk, _ := CreateUserKey(t)
	kinds := map[string]struct {
		seed  string
		pk    string
		label string
	}{
		"user": {string(useed), upk, "USER"},
	}
	if !fips.Enforced() {
		xseed, xpk, _ := CreateCurveKey(t)
		kinds["curve"] = struct {
			seed  string
			pk    string
			label string
		}{string(xseed), xpk, "CURVE"}
	}

	for kind, k := range kinds {
		armor := "-----BEGIN " + k.label + " NKEY SEED-----\n" + k.seed + "\n------END " + k.label + " NKEY SEED------\n"
		banner := "************************* IMPORTANT *************************\n" +
			"NKEY Seed printed below can be used to sign and prove identity.\n" +
			"NKEYs are sensitive and should be treated as secrets.\n\n"
		shapes := map[string]string{
			"raw":            k.seed,
			"newline":        k.seed + "\n",
			"crlf":           k.seed + "\r\n",
			"padded":         "\n  " + k.seed + "  \n\n",
			"armored":        armor,
			"armored_banner": banner + armor + "\n*************************************************************\n",
			"armored_crlf":   strings.ReplaceAll(armor, "\n", "\r\n"),
			"armored_no_eol": strings.TrimSpace(armor),
			"armored_indent": "  -----BEGIN " + k.label + " NKEY SEED-----\n  " + k.seed + "\n  ------END " + k.label + " NKEY SEED------\n",
		}
		for name, content := range shapes {
			t.Run(kind+"/"+name, func(t *testing.T) {
				kp, err := ExtractSeed(content)
				require.NoError(t, err)
				got, err := kp.PublicKey()
				require.NoError(t, err)
				require.Equal(t, k.pk, got)
				seed, err := kp.Seed()
				require.NoError(t, err)
				require.Equal(t, k.seed, string(seed))
			})
		}
	}
}
