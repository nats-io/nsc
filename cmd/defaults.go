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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

const NgsHomeEnv = "NSCHOME"
const NgsPathEnv = "NSCPATH"

type ToolConfig struct {
	StoreRoot     string `json:"store_root"`
	Operator      string `json:"operator"`
	Account       string `json:"account"`
	Cluster       string `json:"cluster"`
	GithubUpdates string `json:"github_updates"`
	LastUpdate    int64  `json:"last_update"`
}

var config ToolConfig
var toolHome string

// GetConfig returns the global config
func GetConfig() *ToolConfig {
	return &config
}

func SetStoreRoot(fp string) error {
	if err := IsValidDir(fp); err != nil {
		return err
	}
	config.StoreRoot = fp
	return nil
}

func SetOperator(operator string) {
	config.Operator = operator
}

func SetAccount(account string) {
	config.Account = account
}

func SetCluster(cluster string) {
	config.Cluster = cluster
}

func LoadOrInit(github string, toolHomeEnv string) error {
	if toolHomeEnv == "" {
		return errors.New("toolHomeEnv is required")
	}
	toolHome = os.Getenv(toolHomeEnv)

	if err := config.Load(); err != nil {
		return err
	}
	// do we have preferences?
	fmt.Printf("%v\n", config)
	if (ToolConfig{}) == config {
		dir, err := homedir.Dir()
		if err != nil {
			// shouldn't prevent if there's an error
			return fmt.Errorf("error getting homedir: %v", err.Error())
		}
		// ~/nats
		config.StoreRoot = filepath.Join(dir, "nats")
		config.GithubUpdates = github
	}
	if err := config.Save(); err != nil {
		return err
	}

	return nil
}

func (d *ToolConfig) Load() error {
	fn, err := d.ConfigFile()
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(fn)
	if err != nil && os.IsNotExist(err) {
		// go check
	} else if err != nil {
		return fmt.Errorf("error reading: %v", err.Error())
	} else {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("error parsing %q: %v", fn, err.Error())
		}
	}
	return nil
}

func (d *ToolConfig) Save() error {
	data, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("error serialzing selfupdate info: %v", err)
	}

	fn, err := d.ConfigFile()
	if err != nil {
		return err
	}

	dir := filepath.Dir(fn)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating dir %q: %v", dir, err)

	}
	if err := ioutil.WriteFile(fn, data, 0600); err != nil {
		return fmt.Errorf("error writing %q: %v", fn, err)
	}

	return nil
}

func (d *ToolConfig) HomeDir() (string, error) {
	exeName := filepath.Base(os.Args[0])
	if toolHome == "" {
		dir, err := homedir.Dir()
		if err != nil {
			// shouldn't prevent if there's an error
			return "", fmt.Errorf("error getting homedir: %v", err.Error())
		}
		toolHome = filepath.Join(dir, fmt.Sprintf(".%scli", exeName))
	}

	fi, err := os.Stat(toolHome)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(toolHome, 0700); err != nil {
			return "", fmt.Errorf("error creating homedir %q: %v", toolHome, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("error stating homedir %q: %v", toolHome, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("error stating homedir path %q exists but it is not a directory", toolHome)
	}

	return toolHome, nil

}

func (d *ToolConfig) ConfigFile() (string, error) {
	var err error
	configFileName := fmt.Sprintf("%s.json", filepath.Base(os.Args[0]))
	dir, err := d.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName), nil
}
