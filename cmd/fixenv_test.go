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
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
	"path/filepath"
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
