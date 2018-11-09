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

	"github.com/nats-io/nkeys"
)

var nkeysDir string

const DefaultNkeysDir = "~/.nkeys"

func GetNkeysDir() string {
	return ResolveDir(DefaultNkeysDir, NkeysDirEnv)
}

func ResolveDir(defaultDir string, envVariableName string) string {
	if nkeysDir != "" {
		return nkeysDir
	}
	v := os.Getenv(envVariableName)
	if v != "" {
		return v
	}
	return defaultDir
}

func GetSignKey(pubkey string) *nkeys.KeyPair {
	return nil
}
