/*
 * Copyright 2018-2022 The NATS Authors
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

package home

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

const NscConfigFileName = "nsc.json"
const StoresSubDirName = "stores"
const KeysDirName = "keys"

var home, _ = homedir.Dir()
var config = envOrValue("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
var data = envOrValue("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))

func envOrValue(name, value string) string {
	ev := os.Getenv(name)
	if ev != "" {
		return ev
	}
	return value
}

func configHome() string {
	return filepath.Join(config, "nats", "nsc")
}

func hasNewConfig() bool {
	dir := configHome()
	fp := filepath.Join(dir, NscConfigFileName)
	if _, err := os.Stat(fp); err == nil {
		return true
	}
	return false
}

func oldConfigDir() (string, error) {
	return filepath.Join(home, ".nsc"), nil
}

func hasOldConfig() bool {
	ocd, err := oldConfigDir()
	if err != nil {
		return false
	}
	old := filepath.Join(ocd, NscConfigFileName)
	_, err = os.Stat(old)
	return err == nil
}

func NscConfigHome() string {
	if !hasNewConfig() && hasOldConfig() {
		old, _ := oldConfigDir()
		return old
	}
	return filepath.Join(config, "nats", "nsc")
}

func NscDataHome(dir string) string {
	return filepath.Join(data, "nats", "nsc", dir)
}
