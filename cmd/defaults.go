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
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
)

//NscHomeEnv the folder for the config file
const NscHomeEnv = "NSC_HOME"

type ToolConfig struct {
	ContextConfig
	GithubUpdates string `json:"github_updates"` // git hub repo
	LastUpdate    int64  `json:"last_update"`
}

var toolName = filepath.Base(os.Args[0])

var config ToolConfig
var toolHome string
var homeEnv string

func SetToolName(name string) {
	toolName = name
}

func GetToolName() string {
	return toolName
}

// GetConfig returns the global config
func GetConfig() *ToolConfig {
	return &config
}

func ResetConfigForTests() {
	config = ToolConfig{}
}

func LoadOrInit(github string, toolHomeEnvName string) (*ToolConfig, error) {
	var err error
	if toolHomeEnvName == "" {
		return nil, errors.New("toolHomeEnv is required")
	}
	homeEnv = toolHomeEnvName

	toolHome, err = initToolHome(toolHomeEnvName)
	if err != nil {
		return nil, err
	}

	if err := config.load(); err != nil {
		return nil, err
	}

	// is the struct modified from the file
	if (ToolConfig{}) == config {
		config.GithubUpdates = github

		config.LastUpdate = time.Now().UTC().Unix() // this is not "true" but avoids the initial check

		// ~/.ngs_cli/nats
		config.StoreRoot = filepath.Join(toolHome, "nats")
		if err := MaybeMakeDir(config.StoreRoot); err != nil {
			return nil, fmt.Errorf("error creating store root: %v", err)
		}

		// load any default entries if there are any
		config.SetDefaults()

		if err := config.Save(); err != nil {
			return nil, err
		}
	}
	// trigger updating defaults
	config.SetDefaults()

	return &config, nil
}

func (d *ToolConfig) SetVersion(version string) {
	// sem version gets very angry if there's a v in the release
	if strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V") {
		version = version[1:]
	}
	GetRootCmd().Version = version
}

func (d *ToolConfig) load() error {
	err := ReadJson(d.configFile(), &config)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (d *ToolConfig) Save() error {
	d.SetDefaults()
	return WriteJson(d.configFile(), d)
}

// GetToolHome returns the . folder used fro this CLIs config and optionally the projects
func initToolHome(envVarName string) (string, error) {
	toolHome = os.Getenv(envVarName)

	if toolHome == "" {
		dir, err := homedir.Dir()
		if err != nil {
			return "", fmt.Errorf("error getting homedir: %v", err.Error())
		}
		toolHome = filepath.Join(dir, fmt.Sprintf(".%s", GetToolName()))
	}

	if err := MaybeMakeDir(toolHome); err != nil {
		return "", fmt.Errorf("error creating tool home %q: %v", toolHome, err)
	}

	return toolHome, nil

}

func (d *ToolConfig) configFile() string {
	configFileName := fmt.Sprintf("%s.json", GetToolName())
	return filepath.Join(toolHome, configFileName)
}
