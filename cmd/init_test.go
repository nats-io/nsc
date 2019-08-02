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
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_InitInteractive(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, _, err := ExecuteInteractiveCmd(createInitCmd(), []interface{}{"O", false})
	require.NoError(t, err)
	// set the operator and the keystore env
	require.NoError(t, GetConfig().SetOperator("O"))
	ts.KeyStore.Env = "O"

	s, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), "O"))
	require.NoError(t, err)
	oc, err := s.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	require.Equal(t, "O", oc.Name)
	require.NotEmpty(t, oc.OperatorServiceURLs)

	kp, err := ts.KeyStore.GetKeyPair(oc.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)

	ac, err := s.ReadAccountClaim("O")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Equal(t, "O", ac.Name)

	kp, err = ts.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)

	uc, err := s.ReadUserClaim("O", "O")
	require.NoError(t, err)
	require.NotNil(t, uc)
	require.Equal(t, "O", uc.Name)

	kp, err = ts.KeyStore.GetKeyPair(uc.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)
	sk, err := kp.Seed()
	require.NoError(t, err)

	fp := ts.KeyStore.GetUserCredsPath("O", "O")
	_, err = os.Stat(fp)
	require.NoError(t, err)

	creds, err := Read(fp)
	require.NoError(t, err)

	require.Contains(t, string(creds), string(sk))
}

func Test_Init(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createInitCmd(), "--name", "O")
	require.NoError(t, err)
	// set the operator and the keystore env
	require.NoError(t, GetConfig().SetOperator("O"))
	ts.KeyStore.Env = "O"

	s, err := store.LoadStore(filepath.Join(ts.GetStoresRoot(), "O"))
	require.NoError(t, err)
	oc, err := s.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	require.Equal(t, "O", oc.Name)
	require.NotEmpty(t, oc.OperatorServiceURLs)

	kp, err := ts.KeyStore.GetKeyPair(oc.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)

	ac, err := s.ReadAccountClaim("O")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Equal(t, "O", ac.Name)

	kp, err = ts.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)

	uc, err := s.ReadUserClaim("O", "O")
	require.NoError(t, err)
	require.NotNil(t, uc)
	require.Equal(t, "O", uc.Name)

	kp, err = ts.KeyStore.GetKeyPair(uc.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)
	sk, err := kp.Seed()
	require.NoError(t, err)

	fp := ts.KeyStore.GetUserCredsPath("O", "O")
	_, err = os.Stat(fp)
	require.NoError(t, err)

	creds, err := Read(fp)
	require.NoError(t, err)

	require.Contains(t, string(creds), string(sk))
}

func Test_InitExists(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createInitCmd(), "--name", "O")
	require.Error(t, err)
}

func Test_InitDeploy(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	as, storage := RunTestAccountServer(t)
	defer as.Close()

	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	_, _, err = ExecuteCmd(createInitCmd(), "--name", "O", "--url", ourl.String())
	require.NoError(t, err)

	sdir := filepath.Join(ts.GetStoresRoot(), "O")
	s, err := store.LoadStore(sdir)
	require.NoError(t, err)
	ac, err := s.ReadAccountClaim("O")
	require.NoError(t, err)
	require.NotNil(t, storage[ac.Subject])
}
