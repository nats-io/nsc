## nsc completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	nsc completion fish | source

To load completions for every new session, execute once:

	nsc completion fish > ~/.config/fish/completions/nsc.fish

You will need to start a new shell for this setup to take effect.


```
nsc completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
  -H, --all-dirs string       sets --config-dir, --data-dir, and --keystore-dir to the same value
      --config-dir string     nsc config directory
      --data-dir string       nsc data store directory
  -i, --interactive           ask questions for various settings
      --keystore-dir string   nsc keystore directory
  -K, --private-key string    Key used to sign. Can be specified as role (where applicable),
                              public key (private portion is retrieved)
                              or file path to a private key or private key 
```

### SEE ALSO

* [nsc completion](nsc_completion.md)	 - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 2-Jan-2025