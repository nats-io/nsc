package cli

import (
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
)

type Validator func(string) error

var cli = &SurveyUI{}

var output io.Writer = os.Stdout

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

func PromptYN(m string) (bool, error) {
	return cli.PromptYN(m)
}

func PromptSecret(m string) (string, error) {
	return cli.PromptSecret(m)
}

func PromptChoices(m string, choices []string) (int, error) {
	return cli.PromptChoices(m, choices)
}

func PromptMultipleChoices(m string, choices []string) ([]int, error) {
	return cli.PromptMultipleChoices(m, choices)
}

type PromptLib interface {
	Prompt(label string, value string, edit bool, validator Validator) (string, error)
	PromptYN(m string) (bool, error)
	PromptSecret(m string) (string, error)
	PromptChoices(m string, choices []string) (int, error)
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
