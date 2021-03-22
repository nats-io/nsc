/*
 * Copyright 2018-2021 The NATS Authors
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

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

func init() {
	GetRootCmd().AddCommand(generateCompletions())
}

func generateCompletions() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completions [bash|zsh|fish|powershell]",
		Short: "Generate shell completions script",
		Long: `To load completions:
Bash:
  $ source <(nsc completion bash)
  # To load completions for each session, execute once:
  # Linux
  $ nsc completions bash > /etc/bash_completion.d/nsc

  # macOS:
  $ nsc completions bash > /usr/local/etc/bash_completion.d/_nsc
Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ nsc completions zsh > "${fpath[1]}/_nsc"

  # You will need to start a new shell for this setup to take effect.

fish:
  $ nsc completions fish | source

  # To load completions for each session, execute once:
  $ nsc completion fish > ~/.config/fish/completions/nsc.fish

PowerShell:
  PS> nsc completions powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> nsc completions powershell > nsc.ps1

  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: false,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, false)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}
	return cmd
}

func defaultCompletionArgument(flag string) func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if cmd.Flag(flag).Value.String() != "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if len(args) == 0 {
			return []string{fmt.Sprintf("--%s", flag)}, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

func registerNoCompletions(cmd *cobra.Command, exclude ...string) {
	flags := cmd.Flags()
	flags.VisitAll(func(f *flag.Flag) {
		excluded := false
		for _, v := range exclude {
			if v == f.Name {
				excluded = true
				break
			}
		}
		if !excluded {
			registerNoCompletionsFor(cmd, f.Name)
		}
	})
}

func registerExtensionFileCompletions(cmd *cobra.Command, flag string, ext ...string) {
	cmd.RegisterFlagCompletionFunc(flag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return ext, cobra.ShellCompDirectiveFilterFileExt
	})
}

func registerNoCompletionsFor(cmd *cobra.Command, flag string) {
	cmd.RegisterFlagCompletionFunc(flag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	})
}

func completeSubjects(srcAccountKeyFlag string) func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		key := cmd.Flag(srcAccountKeyFlag).Value.String()
		if key == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		s, err := GetStore()
		// in the case of add operator, there might not be a store
		if err == ErrNoOperator {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		for _, a := range accounts {
			ac, err := s.ReadAccountClaim(a)
			if err != nil {
				continue
			}
			if ac.Subject == key {
				var buf []string
				for _, v := range ac.Exports {
					buf = append(buf, string(v.Subject))
				}
				return buf, cobra.ShellCompDirectiveNoFileComp
			}
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeSubCommands(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	children := cmd.Commands()
	var buf []string
	for _, c := range children {
		buf = append(buf, c.Name())
	}
	return buf, cobra.ShellCompDirectiveNoFileComp
}

func completeOperator(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return GetConfig().ListOperators(), cobra.ShellCompDirectiveNoFileComp
}

func completeAccount(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	s, err := GetStore()
	// in the case of add operator, there might not be a store
	if err == ErrNoOperator {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	accounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return accounts, cobra.ShellCompDirectiveNoFileComp
}

func completeOtherAccountsKeys(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	s, err := GetStore()
	// in the case of add operator, there might not be a store
	if err == ErrNoOperator {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	target := cmd.Flag("account").Value.String()
	accounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var buf []string
	for _, a := range accounts {
		if a == target {
			continue
		}
		ac, err := s.ReadAccountClaim(a)
		if err != nil {
			continue
		}
		buf = append(buf, ac.Subject)
	}
	return buf, cobra.ShellCompDirectiveNoFileComp
}

func completeUser(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	s, err := GetStore()
	// in the case of add operator, there might not be a store
	if err == ErrNoOperator {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if s.DefaultAccount == "" {
		s.DefaultAccount = cmd.Flag("account").Value.String()
		if s.DefaultAccount == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	users, err := s.ListEntries(store.Accounts, s.DefaultAccount, store.Users)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return users, cobra.ShellCompDirectiveNoFileComp
}

func completeExportSubject(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	s, err := GetStore()
	// in the case of add operator, there might not be a store
	if err == ErrNoOperator {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if s.DefaultAccount == "" {
		s.DefaultAccount = cmd.Flag("account").Value.String()
		if s.DefaultAccount == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	ac, err := s.ReadAccountClaim(s.DefaultAccount)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var buf []string
	for _, v := range ac.Exports {
		buf = append(buf, string(v.Subject))
	}
	return buf, cobra.ShellCompDirectiveNoFileComp
}

func completeExportName(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	s, err := GetStore()
	// in the case of add operator, there might not be a store
	if err == ErrNoOperator {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if s.DefaultAccount == "" {
		s.DefaultAccount = cmd.Flag("account").Value.String()
		if s.DefaultAccount == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	ac, err := s.ReadAccountClaim(s.DefaultAccount)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var buf []string
	for _, v := range ac.Exports {
		buf = append(buf, v.Name)
	}
	return buf, cobra.ShellCompDirectiveNoFileComp
}
