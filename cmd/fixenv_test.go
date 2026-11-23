// Copyright 2019-2025 The NATS Authors
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
	"fmt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/nats-io/nsc/v2/internal/fips"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func Test_FixRequiresInArg(t *testing.T) {
	_, err := ExecuteCmd(createFixCmd(), []string{}...)
	require.Error(t, err)
}

func Test_NoOperatorsErr(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	fp := filepath.Join(ts.Dir, "in")
	require.NoError(t, MaybeMakeDir(fp))

	_, err := ExecuteCmd(createFixCmd(), []string{"--in", fp}...)
	require.Error(t, err)
}

func Test_FixBasics(t *testing.T) {
	ts := NewTestStore(t, "T")
	defer ts.Done(t)

	in := filepath.Join(ts.Dir, "in")
	require.NoError(t, MaybeMakeDir(in))

	osk, opk, okp := CreateOperatorKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "opk.nk"), osk))
	oss, ospk, _ := CreateOperatorKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "ospk.nk"), oss))

	// save one version
	oc := jwt.NewOperatorClaims(opk)
	oc.Name = "O"
	oc.SigningKeys.Add(ospk)
	otok, err := oc.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "o.jwt"), []byte(otok)))

	ask, apk, akp := CreateAccountKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "apk.nk"), ask))
	ac := jwt.NewAccountClaims(apk)
	ac.Name = "A"
	atok, err := ac.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "a.jwt"), []byte(atok)))

	usk, upk, _ := CreateUserKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "upk.nk"), usk))
	uc := jwt.NewUserClaims(upk)
	uc.Name = "U"
	utok, err := uc.Encode(akp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "u.jwt"), []byte(utok)))

	usk2, upk2, _ := CreateUserKey(t)
	uc2 := jwt.NewUserClaims(upk2)
	uc2.Name = "U2"
	u2tok, err := uc2.Encode(akp)
	require.NoError(t, err)
	creds, err := jwt.FormatUserConfig(u2tok, usk2)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "u2.creds"), creds))

	// and copy of operator with a tag (and newer date)
	time.Sleep(time.Second)

	oc.Tags.Add("test")
	otok2, err := oc.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "o2.jwt"), []byte(otok2)))

	ac.Tags.Add("test")
	atok, err = ac.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "a2.jwt"), []byte(atok)))

	uc.Tags.Add("test")
	utok, err = uc.Encode(akp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "u2.jwt"), []byte(utok)))

	ofp := filepath.Join(ts.Dir, "out")
	_, err = ExecuteCmd(createFixCmd(), []string{"--creds", "--in", in, "--out", ofp}...)
	require.NoError(t, err)

	s, err := store.LoadStore(filepath.Join(ofp, "operators", "O"))
	require.NoError(t, err)

	ooc, err := s.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, opk, ooc.Subject)
	require.Equal(t, "O", ooc.Name)
	require.True(t, ooc.Tags.Contains("test"))

	aac, err := s.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, apk, aac.Subject)
	require.Equal(t, "A", aac.Name)
	require.True(t, aac.Tags.Contains("test"))

	uuc, err := s.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, upk, uuc.Subject)
	require.Equal(t, "U", uuc.Name)
	require.True(t, uuc.Tags.Contains("test"))

	uuc2, err := s.ReadUserClaim("A", "U2")
	require.NoError(t, err)
	require.Equal(t, upk2, uuc2.Subject)

	okf := filepath.Join(ofp, "keys", "keys", opk[:1], opk[1:3], fmt.Sprintf("%s.nk", opk))
	require.FileExists(t, okf)
	oskf := filepath.Join(ofp, "keys", "keys", ospk[:1], ospk[1:3], fmt.Sprintf("%s.nk", ospk))
	require.FileExists(t, oskf)

	akf := filepath.Join(ofp, "keys", "keys", apk[:1], apk[1:3], fmt.Sprintf("%s.nk", apk))
	require.FileExists(t, akf)

	ukf := filepath.Join(ofp, "keys", "keys", upk[:1], upk[1:3], fmt.Sprintf("%s.nk", upk))
	require.FileExists(t, ukf)
}

func Test_FixLoadsXKeys(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	ts := NewTestStore(t, "T")
	defer ts.Done(t)

	in := filepath.Join(ts.Dir, "in")
	require.NoError(t, MaybeMakeDir(in))

	xseed, xpub, _ := CreateNkey(t, nkeys.PrefixByteCurve)
	require.NoError(t, WriteFile(filepath.Join(in, "xk.nk"), xseed))

	p := &FixCmd{Keys: map[string]string{}}
	require.NoError(t, p.LoadNKey(filepath.Join(in, "xk.nk")))
	require.Equal(t, string(xseed), p.Keys[xpub])
}

// reproduces #784: export a keystore holding an xkey, then fix it.
// the xkey referenced by the account authorization must end up in the
// new keystore, not just be parsed without error.
func Test_FixStoresExportedXKey(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, uPK, _ := CreateUserKey(t)
	_, err := ExecuteCmd(createEditAuthorizationCallout(), []string{"--auth-user", uPK, "--curve", "generate"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	xPK := ac.Authorization.XKey
	require.NotEmpty(t, xPK)
	xkp, err := ts.KeyStore.GetKeyPair(xPK)
	require.NoError(t, err)
	xSeed, err := xkp.Seed()
	require.NoError(t, err)
	aPK := ts.GetAccountPublicKey(t, "A")

	in := filepath.Join(ts.Dir, "export")
	_, err = ExecuteCmd(createExportKeysCmd(), []string{"--dir", in, "-A", "--include-jwts"}...)
	require.NoError(t, err)
	requireExportedKey(t, in, xPK)

	ofp := filepath.Join(ts.Dir, "out")
	_, err = ExecuteCmd(createFixCmd(), []string{"--in", in, "--out", ofp}...)
	require.NoError(t, err)

	// account still references the xkey
	s, err := store.LoadStore(filepath.Join(ofp, "operators", "O"))
	require.NoError(t, err)
	aac, err := s.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, xPK, aac.Authorization.XKey)

	// account key made it, so the keystore layout is right
	akf := filepath.Join(ofp, "keys", "keys", aPK[:1], aPK[1:3], fmt.Sprintf("%s.nk", aPK))
	require.FileExists(t, akf)

	// xkey must be there too, with the same seed
	xkf := filepath.Join(ofp, "keys", "keys", xPK[:1], xPK[1:3], fmt.Sprintf("%s.nk", xPK))
	require.FileExists(t, xkf)
	d, err := os.ReadFile(xkf)
	require.NoError(t, err)
	require.Equal(t, string(xSeed), strings.TrimSpace(string(d)))
}

// under strict fips an xkey cannot be loaded (X25519 panics), fix must
// warn about it and keep going rather than fail or crash
func Test_FixWarnsOnXKeyUnderFIPS(t *testing.T) {
	if !fips.Enforced() {
		t.Skip("only runs under strict FIPS (fips140=only)")
	}
	in := MakeTempDir(t)
	// a fixed throwaway seed - curve keys cannot be generated under fips
	xseed := "SXACLDJXFFH6ITGTWYAGGRXXZFBF3BXCPPFKNTZWJZ6ICXGBUMHE2PGOG4"
	require.NoError(t, WriteFile(filepath.Join(in, "xk.nk"), []byte(xseed)))

	p := &FixCmd{Keys: map[string]string{}}
	p.in = []string{in}
	r, err := p.LoadNKeys(nil)
	require.NoError(t, err)
	require.Equal(t, store.WARN, r.Code())
	require.Len(t, r.Details, 1)
	require.Contains(t, r.Details[0].Message(), "FIPS")
	require.Empty(t, p.Keys)
}

// a key that cannot be stored must be reported as an error naming that key,
// and must not also be reported or counted as stored
func Test_FixAccountKeyStoreError(t *testing.T) {
	ts := NewTestStore(t, "T")
	defer ts.Done(t)

	in := filepath.Join(ts.Dir, "in")
	require.NoError(t, MaybeMakeDir(in))

	osk, opk, okp := CreateOperatorKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "opk.nk"), osk))
	oc := jwt.NewOperatorClaims(opk)
	oc.Name = "O"
	otok, err := oc.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "o.jwt"), []byte(otok)))

	ask, apk, _ := CreateAccountKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "apk.nk"), ask))
	assk, aspk, _ := CreateAccountKey(t)
	require.NoError(t, WriteFile(filepath.Join(in, "aspk.nk"), assk))
	ac := jwt.NewAccountClaims(apk)
	ac.Name = "A"
	ac.SigningKeys.Add(aspk)
	atok, err := ac.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, WriteFile(filepath.Join(in, "a.jwt"), []byte(atok)))

	// a different seed already sits where the signing key goes, so
	// storing the signing key fails
	ofp := filepath.Join(ts.Dir, "out")
	other, _, _ := CreateAccountKey(t)
	skf := filepath.Join(ofp, "keys", "keys", aspk[:1], aspk[1:3], fmt.Sprintf("%s.nk", aspk))
	require.NoError(t, MaybeMakeDir(filepath.Dir(skf)))
	require.NoError(t, WriteFile(skf, other))

	out, err := ExecuteCmd(createFixCmd(), []string{"--in", in, "--out", ofp}...)
	require.Error(t, err)
	report := out.Out + out.Err + err.Error()

	// the error names the key that failed, not the account
	require.Contains(t, report, fmt.Sprintf("error storing key %s", aspk))
	require.NotContains(t, report, fmt.Sprintf("error storing key %s", apk))
	// the failed key is not reported as stored
	require.NotContains(t, report, fmt.Sprintf("stored key %s", aspk))
	// the account key itself was fine
	require.Contains(t, report, fmt.Sprintf("stored key %s", apk))
	akf := filepath.Join(ofp, "keys", "keys", apk[:1], apk[1:3], fmt.Sprintf("%s.nk", apk))
	require.FileExists(t, akf)

	// the existing file was left alone
	d, err := os.ReadFile(skf)
	require.NoError(t, err)
	require.Equal(t, string(other), string(d))
}

// curve seeds are parsed by the store, in any of the shapes a key file takes
func Test_FixLoadsXKeyFormats(t *testing.T) {
	skipIfFIPS(t, skipReasonFIPSCurve)
	dir := MakeTempDir(t)
	xseed, xpub, _ := CreateNkey(t, nkeys.PrefixByteCurve)
	seed := string(xseed)

	// jwt refuses to decorate a curve seed, but a key file can still be
	// armored by hand or by other tooling - the same shapes jwt emits for
	// the other key kinds must load
	armor := "-----BEGIN CURVE NKEY SEED-----\n" + seed + "\n------END CURVE NKEY SEED------\n"
	banner := "************************* IMPORTANT *************************\n" +
		"NKEY Seed printed below can be used to sign and prove identity.\n" +
		"NKEYs are sensitive and should be treated as secrets.\n\n"
	formats := map[string]string{
		"raw":             seed,
		"newline":         seed + "\n",
		"crlf":            seed + "\r\n",
		"padded":          "\n  " + seed + "  \n\n",
		"armored":         armor,
		"armored_banner":  banner + armor + "\n*************************************************************\n",
		"armored_crlf":    strings.ReplaceAll(armor, "\n", "\r\n"),
		"armored_no_eol":  strings.TrimSpace(armor),
		"armored_indent":  "  -----BEGIN CURVE NKEY SEED-----\n  " + seed + "\n  ------END CURVE NKEY SEED------\n",
		"armored_x_label": "-----BEGIN X NKEY SEED-----\n" + seed + "\n------END X NKEY SEED------\n",
	}
	for name, content := range formats {
		t.Run(name, func(t *testing.T) {
			fp := filepath.Join(dir, name+".nk")
			require.NoError(t, WriteFile(fp, []byte(content)))
			p := &FixCmd{Keys: map[string]string{}}
			require.NoError(t, p.LoadNKey(fp))
			require.Equal(t, seed, p.Keys[xpub])
		})
	}
}

// the curve fallback must not widen what fix accepts: junk and seeds of
// kinds fix does not handle still fail with the original parse error
func Test_FixRejectsNonCurveFallback(t *testing.T) {
	dir := MakeTempDir(t)
	cseed, _, _ := CreateNkey(t, nkeys.PrefixByteCluster)

	for name, content := range map[string]string{
		"junk":    "not a seed",
		"badx":    "SXNOTAREALSEED",
		"cluster": string(cseed),
	} {
		t.Run(name, func(t *testing.T) {
			fp := filepath.Join(dir, name+".nk")
			require.NoError(t, WriteFile(fp, []byte(content)))
			p := &FixCmd{Keys: map[string]string{}}
			err := p.LoadNKey(fp)
			require.Error(t, err)
			require.Contains(t, err.Error(), "error parsing nkey")
			require.Empty(t, p.Keys)
		})
	}
}
