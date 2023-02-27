/*
 * Copyright 2018-2023 The NATS Authors
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

const StoresSubDirName = "stores"
const KeysSubDirName = "keys"

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

func exists(fp string) bool {
	if _, err := os.Stat(fp); err == nil {
		return true
	}
	return false
}

func configHome() string {
	return filepath.Join(config, "nats", "nsc")
}

func dataHome(dir string) string {
	return filepath.Join(data, "nats", "nsc", dir)
}

func hasNewConfigFile() bool {
	return exists(filepath.Join(configHome(), "nsc.json"))
}

func oldConfigDir() string {
	return filepath.Join(home, ".nsc")
}

func hasOldConfigFile() bool {
	return exists(filepath.Join(oldConfigDir(), "nsc.json"))
}

func hasNewDataDir(dir string) bool {
	return exists(dataHome(dir))
}

func oldDataDir(dir string) string {
	if dir == KeysSubDirName {
		return filepath.Join(home, ".nkeys")
	}
	return filepath.Join(home, ".nsc", "nats")
}

func hasOldDataDir(dir string) bool {
	return exists(oldDataDir(dir))
}

func NscConfigHome() string {
	if !hasNewConfigFile() && hasOldConfigFile() {
		return oldConfigDir()
	}
	return filepath.Join(config, "nats", "nsc")
}

func NscDataHome(dir string) string {
	if !hasNewDataDir(dir) && hasOldDataDir(dir) {
		return oldDataDir(dir)
	}
	return dataHome(dir)
}

func NatsCliContextDir() string {
	return filepath.Join(config, "nats", "context")
}

// SetTestConfigDir only for tests!
func SetTestConfigDir(dir string) string {
	old := config
	config = dir
	return old
}
