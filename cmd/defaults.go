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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

//NscHomeEnv the folder for the config file
const NscHomeEnv = "NSC_HOME"

type ToolConfig struct {
	ContextConfig
	GithubUpdates string `json:"github_updates"` // git hub repo
	LastUpdate    int64  `json:"last_update"`
}

var config ToolConfig
var toolHome string

// GetConfig returns the global config
func GetConfig() *ToolConfig {
	return &config
}

func ResetConfigForTests() {
	config = ToolConfig{}
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

	// is the struct modified from the file
	if (ToolConfig{}) == config {
		config.GithubUpdates = github

		// ~/.ngs_cli/nats
		config.StoreRoot = filepath.Join(toolHome, "nats")
		if err := MaybeMakeDir(config.StoreRoot); err != nil {
			return fmt.Errorf("error creating store root: %v", err)
		}

		// load any default entries if there are any
		config.SetDefaults()

		if err := config.Save(); err != nil {
			return err
		}
	}
	// trigger updating defaults

	return nil
}

func (d *ToolConfig) load() error {
	err := ReadJson(d.configFile(), &config)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (d *ToolConfig) Save() error {
	return WriteJson(d.configFile(), d)
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

	if err := MaybeMakeDir(toolHome); err != nil {
		return "", fmt.Errorf("error creating tool home %q: %v", toolHome, err)
	}

	return toolHome, nil

}

func (d *ToolConfig) configFile() string {
	configFileName := fmt.Sprintf("%s.json", filepath.Base(os.Args[0]))
	return filepath.Join(toolHome, configFileName)
}
