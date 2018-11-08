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
	"os"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestAddExportFlags(t *testing.T) {

	os.Setenv(store.DataHomeEnv, MakeTempDir(t))
	os.Setenv(store.DataProfileEnv, "test")
	InitStore(t)

	defer func() {
		os.Setenv(store.DataHomeEnv, "")
		os.Setenv(store.DataProfileEnv, "")
	}()

	tests := CmdTests{
		{createAddExportCmd(), []string{"add", "export"}, nil, []string{"required flag(s) \"name\" not set"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name"}, nil, []string{"flag needs an argument: --name"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "foo"}, nil, []string{"specify one of --stream or --service"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "srv", "--service"}, nil, []string{"flag needs an argument: --service"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "srv", "--service", "srv.foo"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "stream", "--stream"}, nil, []string{"flag needs an argument: --stream"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--stream", "hello"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "hello.>"}, nil, []string{"services cannot contain wildcards"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "hello.*"}, nil, []string{"services cannot contain wildcards"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "hello.*.bar"}, nil, []string{"services cannot contain wildcards"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "hello>"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "foo.*b.bar>"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "foo.a>.bar>"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "hello", "--service", "foo.>.bar"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "wstream", "--stream", "foo.>"}, nil, nil, false},
		{createAddExportCmd(), []string{"add", "export", "--name", "wstream", "--stream", "foo.>", "--tag"}, nil, []string{"flag needs an argument: --tag"}, true},
		{createAddExportCmd(), []string{"add", "export", "--name", "wstream", "--stream", "foo.>", "--tag", "a,b"}, nil, nil, true},
	}
	tests.Run(t, "root", "add")
}

func TestGenerateAccount_Exports(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	_, kp := InitStore(t)

	_, _, err := ExecuteCmd(createAddExportCmd(), "--name", "tstream", "--stream", "foo.bar.>", "--tag", "stream")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddExportCmd(), "--name", "tservice", "--service", "barz", "--tag", "service")
	require.NoError(t, err)

	var exports Exports
	require.NoError(t, exports.Load())
	require.Len(t, exports, 2)

	out, _, err := ExecuteCmd(hoistFlags(createGenerateAccountCmd()), "-K", SeedKey(t, kp))
	t.Log(out)
	out = ExtractToken(out)

	ac, err := jwt.DecodeAccountClaims(out)
	require.NoError(t, err)

	require.Len(t, ac.Exports, 2)
}
