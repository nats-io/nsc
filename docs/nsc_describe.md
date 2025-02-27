## nsc describe

Describe assets such as operators, accounts, users, and jwt files

### Options

```
  -F, --field string   extract value from specified field using json structure
  -h, --help           help for describe
  -J, --json           display JWT body as JSON
  -W, --long-ids       display account ids on imports
  -R, --raw            output the raw JWT (exclusive of long-ids)
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
* [nsc describe account](nsc_describe_account.md)	 - Describes an account
* [nsc describe jwt](nsc_describe_jwt.md)	 - Describe a jwt/creds file
* [nsc describe operator](nsc_describe_operator.md)	 - Describes the operator
* [nsc describe user](nsc_describe_user.md)	 - Describes an user

###### Auto generated by spf13/cobra on 2-Jan-2025
