## nsc revocations add-user

Revoke a user

```
nsc revocations add-user [flags]
```

### Options

```
  -a, --account string           account name
      --at date-time             revokes all user credentials created or edited before a Unix timestamp ('0' is treated as now, accepted formats are RFC3339 or #seconds since epoch) (default 1969-12-31T16:00:00-08:00)
  -h, --help                     help for add-user
  -n, --name string              user name
  -u, --user-public-key string   user-public-key
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

* [nsc revocations](nsc_revocations.md)	 - Manage revocation for users and activations from an account

