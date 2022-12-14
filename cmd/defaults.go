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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/nats-io/nsc/v2/home"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
)

// NscHomeEnv the folder for the config file
const NscHomeEnv = "NSC_HOME"
const NscCwdOnlyEnv = "NSC_CWD_ONLY"
const NscNoGitIgnoreEnv = "NSC_NO_GIT_IGNORE"
const NscRootCasNatsEnv = "NATS_CA"
const NscTlsKeyNatsEnv = "NATS_KEY"
const NscTlsCertNatsEnv = "NATS_CERT"

type ToolConfig struct {
	ContextConfig
	GithubUpdates string `json:"github_updates"` // git hub repo
	LastUpdate    int64  `json:"last_update"`
}

var config ToolConfig
var rootCAsNats nats.Option // Will be skipped, when nil and passed to a connection
var tlsKeyNats nats.Option  // Will be skipped, when nil and passed to a connection
var tlsCertNats nats.Option // Will be skipped, when nil and passed to a connection
var rootCAsFile string

func GetToolName() string {
	return "nsc"
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
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, v := range dirEntries {
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
		d, err := os.ReadFile(tf)
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

func GetConfigDir() string {
	if ConfigDirFlag == "" {
		// this is running under a test...
		return os.Getenv(NscHomeEnv)
	}
	return ConfigDirFlag
}

func LoadOrInit(configDir string, dataDir string, keystoreDir string) (*ToolConfig, error) {
	const github = "nats-io/nsc"

	if configDir == "" {
		configDir = home.NscConfigHome()
	}
	ConfigDirFlag = configDir
	if err := MaybeMakeDir(ConfigDirFlag); err != nil {
		return nil, err
	}

	dataDirFlagSet := dataDir != ""
	if dataDir == "" {
		dataDir = home.NscDataHome(home.StoresSubDirName)
	}
	// dir created if files written
	DataDirFlag = dataDir

	if keystoreDir == "" {
		keystoreDir = home.NscDataHome(home.KeysSubDirName)
	}
	// dir created if keys added
	KeysDirFlag = keystoreDir
	store.KeyStorePath = KeysDirFlag

	if err := config.load(); err != nil {
		return nil, err
	}

	// is the struct modified from the file
	if (ToolConfig{}) == config {
		config.GithubUpdates = github

		config.LastUpdate = time.Now().UTC().Unix() // this is not "true" but avoids the initial check
		config.StoreRoot = dataDir
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
	if dataDirFlagSet {
		config.StoreRoot = dataDir
	}

	// trigger updating defaults
	config.SetDefaults()

	return &config, nil
}

func SetVersion(version string) {
	// sem version gets very angry if there's a v in the release
	if strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V") {
		version = version[1:]
	}
	GetRootCmd().Version = version
}

func (d *ToolConfig) SetVersion(version string) {
	SetVersion(version)
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

func (d *ToolConfig) configFile() string {
	return filepath.Join(GetConfigDir(), "nsc.json")
}
