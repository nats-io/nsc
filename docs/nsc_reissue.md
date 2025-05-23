## nsc reissue

Re-issue objects with a new identity key

### Options

```
  -h, --help   help for reissue
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

* [nsc](nsc.md)	 - nsc creates NATS operators, accounts, users, and manage their permissions.
* [nsc reissue operator](nsc_reissue_operator.md)	 - Re-issues the operator with a new identity and re-signs affected accounts.
	When `--private-key` flag is provided with an operator seed, the identity
	specified will be used for the operator and as the issuer for the accounts.
	Note use of this command could create a disruption. Please backup your server
	and nsc environment prior to use.

###### Auto generated by spf13/cobra on 2-Jan-2025
