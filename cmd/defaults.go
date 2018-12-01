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

//NscHomeEnv the folder for the config file
const NscHomeEnv = "NSCHOME"

type ToolConfig struct {
	StoreRoot     string `json:"store_root"` // where the projects are
	Operator      string `json:"operator"`
	Account       string `json:"account"`
	Cluster       string `json:"cluster"`
	GithubUpdates string `json:"github_updates"` // git hub repo
	LastUpdate    int64  `json:"last_update"`
}

var config ToolConfig
var toolHome string

// GetConfig returns the global config
func GetConfig() *ToolConfig {
	return &config
}

func SetStoreRoot(fp string) error {
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
	var err error

	if toolHomeEnv == "" {
		return errors.New("toolHomeEnv is required")
	}

	toolHome, err = initToolHome(toolHomeEnv)

	if err != nil {
		return err
	}

	if err := config.load(); err != nil {
		return err
	}

	// do we have preferences?

	if (ToolConfig{}) == config {
		config.GithubUpdates = github

		// ~/.ngs_cli/nats
		config.StoreRoot = filepath.Join(toolHome, "nats")

		if err := os.Mkdir(config.StoreRoot, 0700); err != nil {
			return fmt.Errorf("error creating store root %q: %v", config.StoreRoot, err)
		}

		if err := config.Save(); err != nil {
			return err
		}
	}

	return nil
}

func (d *ToolConfig) load() error {
	fn := d.configFile()
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

	fn := d.configFile()

	if err := ioutil.WriteFile(fn, data, 0600); err != nil {
		return fmt.Errorf("error writing %q: %v", fn, err)
	}

	return nil
}

// GetToolHome returns the . folder used fro this CLIs config and optionally the projects
func initToolHome(envVarName string) (string, error) {
	toolHome = os.Getenv(envVarName)

	if toolHome == "" {
		exeName := filepath.Base(os.Args[0])
		dir, err := homedir.Dir()
		if err != nil {
			// shouldn't prevent if there's an error
			return "", fmt.Errorf("error getting homedir: %v", err.Error())
		}
		toolHome = filepath.Join(dir, fmt.Sprintf(".%scli", exeName))
	}

	fi, err := os.Stat(toolHome)

	if err != nil && os.IsNotExist(err) {
		if err := os.Mkdir(toolHome, 0700); err != nil {
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

func (d *ToolConfig) configFile() string {
	configFileName := fmt.Sprintf("%s.json", filepath.Base(os.Args[0]))
	return filepath.Join(toolHome, configFileName)
}
