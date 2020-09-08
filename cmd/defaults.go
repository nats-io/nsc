/*
 * Copyright 2018-2020 The NATS Authors
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
	"strings"
	"time"

	"github.com/nats-io/jwt"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nsc/cmd/store"
)

//NscHomeEnv the folder for the config file
const NscHomeEnv = "NSC_HOME"
const NscCwdOnlyEnv = "NSC_CWD_ONLY"
const NscNoGitIgnoreEnv = "NSC_NO_GIT_IGNORE"

type ToolConfig struct {
	ContextConfig
	GithubUpdates string `json:"github_updates"` // git hub repo
	LastUpdate    int64  `json:"last_update"`
}

var toolName = strings.ReplaceAll(filepath.Base(os.Args[0]), ".exe", "")

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

func GetCwdCtx() *ContextConfig {
	var ctx ContextConfig
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	dir := cwd
	info, ok, err := isOperatorDir(dir)
	if err != nil {
		return nil
	}
	if ok {
		ctx.StoreRoot = filepath.Dir(dir)
		ctx.Operator = info.Name
		return &ctx
	}

	// search down
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, v := range infos {
		if !v.IsDir() {
			continue
		}
		_, ok, err := isOperatorDir(filepath.Join(dir, v.Name()))
		if err != nil {
			return nil
		}
		if ok {
			ctx.StoreRoot = dir
			return &ctx
		}
	}

	// search up
	dir = cwd
	for {
		info, ok, err := isOperatorDir(dir)
		if err != nil {
			return nil
		}
		if ok {
			ctx.StoreRoot = filepath.Dir(dir)
			ctx.Operator = info.Name
			sep := string(os.PathSeparator)
			name := fmt.Sprintf("%s%s%s%s%s", sep, info.Name, sep, store.Accounts, sep)
			idx := strings.Index(cwd, name)
			if idx != -1 {
				prefix := cwd[:idx+len(name)]
				sub, err := filepath.Rel(prefix, cwd)
				if err == nil && len(sub) > 0 {
					names := strings.Split(sub, sep)

					if len(names) > 0 {
						ctx.Account = names[0]
					}
				}
			}
			return &ctx
		}
		pdir := filepath.Dir(dir)
		if pdir == dir {
			// not found
			return nil
		}
		dir = pdir
	}
}

func isOperatorDir(dir string) (store.Info, bool, error) {
	var v store.Info
	fi, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	if !fi.IsDir() {
		return v, false, nil
	}
	tf := filepath.Join(dir, ".nsc")
	fi, err = os.Stat(tf)
	if os.IsNotExist(err) {
		return v, false, nil
	}
	if err != nil {
		return v, false, nil
	}
	if !fi.IsDir() {
		d, err := ioutil.ReadFile(tf)
		if err != nil {
			return v, false, err
		}
		err = json.Unmarshal(d, &v)
		if err != nil {
			return v, false, err
		}
		if v.Name != "" && v.Kind == jwt.OperatorClaim {
			return v, true, nil
		}
	}
	return v, false, nil
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
	} else {
		ctx := GetCwdCtx()
		if ctx != nil {
			config.StoreRoot = ctx.StoreRoot
			if ctx.Operator != "" {
				config.Operator = ctx.Operator
				if ctx.Account != "" {
					config.Account = ctx.Account
				}
			}
			config.SetDefaults()
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
	if NscCwdOnly {
		// don't read it
		return nil
	}
	err := ReadJson(d.configFile(), &config)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (d *ToolConfig) Save() error {
	d.SetDefaults()
	if !NscCwdOnly {
		return WriteJson(d.configFile(), d)
	}
	return nil
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
		return "", fmt.Errorf("error creating tool home %#q: %v", toolHome, err)
	}

	return toolHome, nil

}

func (d *ToolConfig) configFile() string {
	configFileName := fmt.Sprintf("%s.json", GetToolName())
	return filepath.Join(toolHome, configFileName)
}
