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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
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
	var f *os.File

	if fp == "--" {
		f = os.Stdout
	} else {
		afp, err := filepath.Abs(fp)
		if err != nil {
			return nil, fmt.Errorf("error calculating abs %q: %v", fp, err)
		}
		_, err = os.Stat(afp)
		if err == nil {
			return nil, fmt.Errorf("%q already exists", afp)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}

		f, err = os.Create(afp)
		if err != nil {
			return nil, fmt.Errorf("error creating output file %q: %v", afp, err)
		}
	}
	return f, nil
}

func IsStdOut(fp string) bool {
	return fp == "--"
}

func WriteJson(fp string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("error marshalling: %v", err)
	}

	if err := ioutil.WriteFile(fp, data, 0600); err != nil {
		return fmt.Errorf("error writing %q: %v", fp, err)
	}

	return nil
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

func ReadJson(fp string, v interface{}) error {
	data, err := Read(fp)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	return nil
}

func Read(fp string) ([]byte, error) {
	afp, err := filepath.Abs(fp)
	if err != nil {
		return nil, fmt.Errorf("error converting abs %q: %v", fp, err)
	}
	return ioutil.ReadFile(afp)
}

func FormatConfig(jwtType string, jwtString string, seed string) []byte {
	w := bytes.NewBuffer(nil)

	w.Write(FormatJwt(jwtType, jwtString))

	_, _ = fmt.Fprintln(w, "************************* IMPORTANT *************************")
	_, _ = fmt.Fprintln(w, "NKEY Seed printed below can be used to sign and prove identity.")
	_, _ = fmt.Fprintln(w, "NKEYs are sensitive and should be treated as secrets.")
	_, _ = fmt.Fprintln(w)

	label := strings.ToUpper(jwtType)
	_, _ = fmt.Fprintf(w, "-----BEGIN %s NKEY SEED-----\n", label)
	_, _ = fmt.Fprintln(w, seed)
	_, _ = fmt.Fprintf(w, "------END %s NKEY SEED------\n", label)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "*************************************************************")

	return w.Bytes()
}

func FormatJwt(jwtType string, jwtString string) []byte {
	w := bytes.NewBuffer(nil)

	label := strings.ToUpper(jwtType)
	_, _ = fmt.Fprintf(w, "-----BEGIN NATS %s JWT-----\n", label)
	_, _ = fmt.Fprintln(w, jwtString)
	_, _ = fmt.Fprintf(w, "------END NATS %s JWT------\n", label)
	_, _ = fmt.Fprintln(w)
	return w.Bytes()
}

var nscDecoratedRe = regexp.MustCompile(`\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))`)

// ExtractToken pulls a JWT out of a string containing begin/end markers
func ExtractToken(data string) (string, error) {
	// Fixme - update to wipe data on each extract/use
	contents := []byte(data)
	items := nscDecoratedRe.FindAllSubmatch(contents, -1)
	if len(items) == 0 {
		return string(contents), nil
	}
	// First result should be the user JWT.
	raw := items[0][1]
	tmp := make([]byte, len(raw))
	copy(tmp, raw)
	return string(tmp), nil
}

// ExtractSeed pulls a seed out of a string containing begin/end markers, including a chain file
func ExtractSeed(data string) (nkeys.KeyPair, error) {
	// Fixme - update to wipe data on each extract/use
	contents := []byte(data)
	var seed []byte

	items := nscDecoratedRe.FindAllSubmatch(contents, -1)
	if len(items) > 1 {
		seed = items[1][1]
	} else {
		lines := bytes.Split(contents, []byte("\n"))
		for _, line := range lines {
			if bytes.HasPrefix(bytes.TrimSpace(line), []byte("SU")) {
				seed = line
				break
			}
		}
	}

	if seed == nil {
		return nil, fmt.Errorf("nats: No nkey user seed found")
	}

	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	return kp, nil
}

func ParseNumber(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToUpper(s)
	re := regexp.MustCompile(`(-?\d+$)`)
	m := re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return v, nil
	}
	re = regexp.MustCompile(`(-?\d+)([B|K|M|G])`)
	m = re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, err
		}
		if v < 0 {
			return -1, nil
		}
		if m[2] == "B" {
			return v, nil
		}
		if m[2] == "K" {
			return v * 1000, nil
		}
		if m[2] == "M" {
			return v * 1000000, nil
		}
		if m[2] == "G" {
			return v * 1000000000, nil
		}
	}
	return 0, fmt.Errorf("couldn't parse number: %v", s)
}

func UnixToDate(d int64) string {
	if d == 0 {
		return ""
	}
	return time.Unix(d, 0).UTC().String()
}

func HumanizedDate(d int64) string {
	if d == 0 {
		return ""
	}
	now := time.Now()
	when := time.Unix(d, 0).UTC()

	if now.After(when) {
		return strings.TrimSpace(strings.Title(humanize.RelTime(when, now, "ago", "")))
	} else {
		return strings.TrimSpace(strings.Title("in " + humanize.RelTime(now, when, "", "")))
	}
}

func NKeyValidator(kind nkeys.PrefixByte) cli.Validator {
	return func(v string) error {
		nk, err := store.ResolveKey(v)
		if err != nil {
			return err
		}
		t, err := store.KeyType(nk)
		if err != nil {
			return err
		}
		if t != kind {
			return fmt.Errorf("specified key is not valid for an %s", kind.String())
		}
		return nil
	}
}

func EditKeyPath(kind nkeys.PrefixByte, label string, keypath *string) error {
	ok, err := cli.PromptYN(fmt.Sprintf("generate an %s nkey", label))
	if err != nil {
		return err
	}

	if !ok {
		v, err := cli.Prompt(fmt.Sprintf("path to the %s nkey", label), "", true, NKeyValidator(kind))
		if err != nil {
			return err
		}
		*keypath = v
	}
	return nil
}

func LoadFromURL(url string) ([]byte, error) {
	c := &http.Client{Timeout: time.Second * 5}
	r, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error loading %q: %v", url, err)
	}
	defer r.Body.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %q: %v", url, err)
	}
	data := buf.Bytes()
	return data, nil
}

func IsValidDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return nil
}

func MaybeMakeDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("error creating %q: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("error stat'ing %q: %v", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%q already exists and it is not a dir", dir)
	}
	return nil
}

func AbbrevHomePaths(fp string) string {
	h, err := homedir.Dir()
	if err != nil {
		return fp
	}
	if strings.HasPrefix(fp, h) {
		return strings.Replace(fp, h, "~", 1)
	}
	return fp
}
