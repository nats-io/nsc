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
	"fmt"
	"os"
)

// Resolve a directory/file from an environment variable
// if not set defaultPath is returned
func ResolvePath(defaultPath string, varName string) string {
	v := os.Getenv(varName)
	if v != "" {
		return v
	}
	return defaultPath
}

func GetOutput(fp string) (*os.File, error) {
	var err error
	var f *os.File

	if fp == "--" {
		f = os.Stdout
	} else {
		_, err = os.Stat(fp)
		if err == nil {
			return nil, fmt.Errorf("%q already exists", fp)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}

		f, err = os.Create(fp)
		if err != nil {
			return nil, fmt.Errorf("error creating output file %q: %v", fp, err)
		}
	}
	return f, nil
}

func IsStdOut(fp string) bool {
	return fp == "--"
}

func Write(fp string, data []byte) error {
	var err error
	var f *os.File

	f, err = GetOutput(fp)
	if err != nil {
		return err
	}
	if !IsStdOut(fp) {
		defer f.Close()
	}
	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("error writing %q: %v", fp, err)
	}

	if !IsStdOut(fp) {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}
