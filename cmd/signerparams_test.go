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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func createSignerCmd(kind nkeys.PrefixByte, allowManaged bool, expected nkeys.KeyPair) *cobra.Command {
	params := signerParamsTest{kind: kind, allowManaged: allowManaged, expected: expected}
	cmd := &cobra.Command{
		Use: "sp",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	HoistRootFlags(cmd)
	return cmd
}

type signerParamsTest struct {
	expected     nkeys.KeyPair
	kind         nkeys.PrefixByte
	allowManaged bool
	sp           SignerParams
}

func (a *signerParamsTest) SetDefaults(ctx ActionCtx) error {
	a.sp.SetDefaults(a.kind, a.allowManaged, ctx)
	return nil
}

func (a *signerParamsTest) PreInteractive(ctx ActionCtx) error {
	return a.sp.Edit(ctx)
}

func (a *signerParamsTest) Load(ctx ActionCtx) error {
	return nil
}

func (a *signerParamsTest) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (a *signerParamsTest) Validate(ctx ActionCtx) error {
	return a.sp.Resolve(ctx)
}

func (a *signerParamsTest) Run(ctx ActionCtx) error {
	if a.expected == nil && a.sp.signerKP != nil {
		d, _ := a.sp.signerKP.Seed()
		return fmt.Errorf("no key expected - found %q", string(d))
	}
	if a.expected != nil && a.sp.signerKP == nil {
		return fmt.Errorf("expected key - none found")
	}
	return nil
}

func Test_SignerParams(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	akp, err := ts.KeyStore.GetAccountKey("A")
	require.NoError(t, err)
	require.NotNil(t, akp)

	ts.AddCluster(t, "C")
	ckp, err := ts.KeyStore.GetClusterKey("C")
	require.NoError(t, err)
	require.NotNil(t, ckp)

	tests := CmdTests{
		{createSignerCmd(nkeys.PrefixByteOperator, false, ts.OperatorKey), []string{"sp"}, nil, nil, false},
		{createSignerCmd(nkeys.PrefixByteAccount, false, akp), []string{"sp"}, nil, nil, false},
		{createSignerCmd(nkeys.PrefixByteCluster, false, ckp), []string{"sp"}, nil, nil, false},
	}

	tests.Run(t, "root")
}

func Test_ManagedSignerParams(t *testing.T) {
	ts := NewTestStoreWithOperator(t, "test", nil)
	defer ts.Done(t)
	require.True(t, ts.Store.IsManaged())
	require.Nil(t, ts.OperatorKey)

	ts.AddAccount(t, "A")
	akp, err := ts.KeyStore.GetAccountKey("A")
	require.NoError(t, err)
	require.NotNil(t, akp)

	tests := CmdTests{
		{createSignerCmd(nkeys.PrefixByteOperator, true, akp), []string{"sp"}, nil, nil, false},
	}

	tests.Run(t, "root")
}

func Test_SignerOperator(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	dest := filepath.Join(ts.Dir, filepath.Base(ts.OperatorKeyPath))
	require.NoError(t, os.Rename(ts.OperatorKeyPath, dest))
	require.FileExists(t, dest)

	tests := CmdTests{
		{createSignerCmd(nkeys.PrefixByteOperator, false, nil), []string{"sp"}, nil, nil, false},
		{createSignerCmd(nkeys.PrefixByteOperator, false, ts.OperatorKey), []string{"sp", "-K", dest}, nil, nil, false},
	}

	tests.Run(t, "root")
}

func Test_SignerParamsSameDir(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	dest := filepath.Join(ts.Dir, filepath.Base(ts.OperatorKeyPath))
	require.NoError(t, os.Rename(ts.OperatorKeyPath, dest))
	require.FileExists(t, dest)

	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(ts.Dir))
	_, _, err = ExecuteCmd(createSignerCmd(nkeys.PrefixByteOperator, false, ts.OperatorKey), "-K", filepath.Base(dest))
	require.NoError(t, os.Chdir(cwd))
	require.NoError(t, err)
}

func Test_SignerParamsRelativePath(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	dest := filepath.Join(ts.Dir, filepath.Base(ts.OperatorKeyPath))
	require.NoError(t, os.Rename(ts.OperatorKeyPath, dest))
	require.FileExists(t, dest)

	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(filepath.Join(ts.Dir, "store")))
	_, _, err = ExecuteCmd(createSignerCmd(nkeys.PrefixByteOperator, false, ts.OperatorKey), "-K", filepath.Join("../", filepath.Base(dest)))
	require.NoError(t, os.Chdir(cwd))
	require.NoError(t, err)
}

func Test_SignerParamsPathNotFound(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	require.NoError(t, os.Remove(ts.OperatorKeyPath))
	_, _, err := ExecuteCmd(createSignerCmd(nkeys.PrefixByteOperator, false, nil), "-K", ts.OperatorKeyPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file or directory")
}
