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

//func AddExport(t *testing.T, ts *TestStore, accountName string, kind jwt.ExportType, subject string) {
//	if !ts.Store.Has(store.Accounts, accountName, store.JwtName(accountName)) {
//		_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", accountName)
//		require.NoError(t, err, "account creation for export")
//	}
//
//	if kind == jwt.Stream {
//		_, _, err := ExecuteCmd(createAddExportCmd(), "--subject", subject)
//		require.NoError(t, err)
//	} else {
//		_, _, err := ExecuteCmd(createAddExportCmd(), "--subject", subject, "--service")
//		require.NoError(t, err)
//	}
//}
//
//
//
//func Test_AddImport(t *testing.T) {
//	ts := NewTestStore(t, "add_export")
//	defer ts.Done(t)
//
//	_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", "A")
//	require.NoError(t, err, "export creation")
//
//	tests := CmdTests{
//		{createAddExportCmd(), []string{"add", "export"}, nil, []string{"subject is required"}, true},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "foo"}, nil, []string{"added public stream export \"foo\""}, false},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "bar", "--service"}, nil, []string{"added public service export \"bar\""}, false},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "bar"}, nil, []string{"export subject \"bar\" already exports \"bar\""}, true},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "foo", "--service"}, nil, []string{"export subject \"foo\" already exports \"foo\""}, true},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "baz.>", "--service"}, nil, []string{"services cannot have wildcard subject: \"baz.>\""}, true},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "baz.>"}, nil, []string{"added public stream export \"baz.>\""}, false},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "ar", "--name", "mar"}, nil, []string{"added public stream export \"mar\""}, false},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "mar", "--name", "ar", "--service"}, nil, []string{"added public service export \"ar\""}, false},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "pubstream", "--private"}, nil, []string{"added private stream export \"pubstream\""}, false},
//		{createAddExportCmd(), []string{"add", "export", "--subject", "pubservice", "--private", "--service"}, nil, []string{"added private service export \"pubservice\""}, false},
//	}
//
//	tests.Run(t, "root", "add")
//}
