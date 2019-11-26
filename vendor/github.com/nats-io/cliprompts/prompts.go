package cliprompts

import (
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
)

type Logger func(args ...interface{})

type Validator func(string) error

var cli PromptLib

// set a Logger during a test (cli.LogFn = t.Log) to debug interactive prompts
var LogFn Logger

var output io.Writer = os.Stdout

type PromptLib interface {
	Prompt(label string, value string, edit bool, validator Validator) (string, error)
	PromptWithHelp(label string, value string, edit bool, validator Validator, help string) (string, error)
	PromptYN(m string, defaultValue bool) (bool, error)
	PromptSecret(m string) (string, error)
	PromptChoices(m string, value string, choices []string) (int, error)
	PromptMultipleChoices(m string, choices []string) ([]int, error)
}

func init() {
	ResetPromptLib()
	LogFn = nil
}

func SetPromptLib(p PromptLib) {
	cli = p
}

func ResetPromptLib() {
	SetPromptLib(&SurveyUI{})
	LogFn = nil
}

func SetOutput(out io.Writer) {
	output = out
}

func Underline(s string) string {
	return fmt.Sprintf("\xff\033[4m\xff%s\xff\033[0m\xff", s)
}

func Bold(s string) string {
	return fmt.Sprintf("\033[1m%s\033[0m", s)
}

func Italic(s string) string {
	return fmt.Sprintf("\033[3m%s\033[0m", s)
}

func Prompt(label string, value string, edit bool, validator Validator) (string, error) {
	return cli.Prompt(label, value, edit, validator)
}

func PromptWithHelp(label string, value string, edit bool, validator Validator, help string) (string, error) {
	return cli.PromptWithHelp(label, value, edit, validator, help)
}

func PromptYN(m string) (bool, error) {
	return cli.PromptYN(m, true)
}

func PromptBoolean(m string, defaultValue bool) (bool, error) {
	return cli.PromptYN(m, defaultValue)
}

func PromptSecret(m string) (string, error) {
	return cli.PromptSecret(m)
}

func PromptChoices(m string, value string, choices []string) (int, error) {
	return cli.PromptChoices(m, value, choices)
}

func PromptMultipleChoices(m string, choices []string) ([]int, error) {
	return cli.PromptMultipleChoices(m, choices)
}

func EmailValidator() Validator {
	return func(input string) error {
		if input != "" {
			_, err := mail.ParseAddress(input)
			return err
		}
		return nil
	}
}

func LengthValidator(min int) Validator {
	return func(input string) error {
		if len(input) >= min {
			return nil
		}
		return errors.New("value is too short")
	}
}

func PathOrURLValidator() Validator {
	return func(s string) error {
		if u, err := url.Parse(s); err == nil && u.Scheme != "" {
			return nil
		}

		v, err := homedir.Expand(s)
		if err != nil {
			return err
		}
		v, err = filepath.Abs(v)
		if err != nil {
			return err
		}
		info, err := os.Stat(v)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("path is not a file")
		}
		return nil
	}
}

func URLValidator(protocol ...string) Validator {
	return func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return errors.New("url cannot be empty")
		}
		u, err := url.Parse(s)
		if err != nil {
			return err
		}
		scheme := strings.ToLower(u.Scheme)

		ok := false
		for _, v := range protocol {
			if scheme == v {
				ok = true
				break
			}
		}
		if !ok {
			var protos []string
			protos = append(protos, protocol...)
			return fmt.Errorf("scheme %q is not supported (%v)", scheme, strings.Join(protos, ", "))
		}
		if u.Host == "" {
			return fmt.Errorf("no host specified (%v)", s)
		}

		return nil
	}
}
