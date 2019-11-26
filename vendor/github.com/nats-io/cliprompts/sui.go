package cliprompts

import (
	"github.com/AlecAivazis/survey"
)

type SurveyUI struct{}

func (sui *SurveyUI) Prompt(label string, value string, edit bool, validator Validator) (string, error) {
	v := value
	p := &survey.Input{
		Message: label,
		Default: value,
	}
	if err := survey.AskOne(p, &v, sui.wrap(validator)); err != nil {
		return "", err
	}
	return v, nil
}

func (sui *SurveyUI) PromptWithHelp(label string, value string, edit bool, validator Validator, help string) (string, error) {
	v := value
	p := &survey.Input{
		Message: label,
		Default: value,
		Help:    help,
	}
	if err := survey.AskOne(p, &v, sui.wrap(validator)); err != nil {
		return "", err
	}
	return v, nil
}

func (sui *SurveyUI) wrap(validator Validator) survey.Validator {
	if validator == nil {
		return nil
	}
	return func(input interface{}) error {
		s := input.(string)
		return validator(s)
	}
}

func (sui *SurveyUI) PromptYN(m string, defaultValue bool) (bool, error) {
	v := defaultValue
	p := &survey.Confirm{
		Message: m,
		Default: defaultValue,
	}
	if err := survey.AskOne(p, &v, nil); err != nil {
		return false, err
	}
	return v, nil
}

func (sui *SurveyUI) PromptSecret(m string) (string, error) {
	v := ""
	p := &survey.Password{
		Message: m,
	}
	if err := survey.AskOne(p, &v, nil); err != nil {
		return "", err
	}
	return v, nil
}

func (sui *SurveyUI) PromptChoices(m string, value string, choices []string) (int, error) {
	v := ""
	p := &survey.Select{
		Message: m,
		Options: choices,
	}

	if value != "" {
		p.Default = value
	}
	if err := survey.AskOne(p, &v, nil); err != nil {
		return -1, err
	}
	idx := -1
	for i, t := range choices {
		if t == v {
			idx = i
			break
		}
	}
	return idx, nil
}

func (sui *SurveyUI) PromptMultipleChoices(m string, choices []string) ([]int, error) {
	v := make([]string, 0)
	p := &survey.MultiSelect{
		Message: m,
		Options: choices,
	}
	if err := survey.AskOne(p, &v, nil); err != nil {
		return nil, err
	}

	idx := make([]int, 0)
	for _, t := range v {
		for i, c := range choices {
			if c == t {
				idx = append(idx, i)
			}
		}
	}
	return idx, nil
}
