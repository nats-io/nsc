## nsc push

Push an account jwt to an Account JWT Server

```
nsc push (currentAccount)
push -a <accountName>
push -A (all accounts)
push -P
push -P -A (all accounts) [flags]
```

### Examples

```
push
```

### Options

```
  -a, --account string                  account name
  -u, --account-jwt-server-url string   set account jwt server url for nsc sync (only http/https/nats urls supported if updating with nsc) If a nats url is provided 
  -R, --account-removal string          remove specific account. Only works with nats-resolver enabled nats-server. Mutually exclusive of prune/diff.
  -A, --all                             push all accounts under the current operator (exclusive of -a)
  -D, --diff                            diff accounts present in nsc env and nats-account-resolver. Mutually exclusive of account-removal/prune.
  -F, --force                           push regardless of validation issues
  -h, --help                            help for push
  -P, --prune                           prune all accounts not under the current operator. Only works with nats-resolver enabled nats-server. Mutually exclusive of account-removal/diff.
      --system-account string           System account for use with nats-resolver enabled nats-server. (Default is system account specified by operator)
      --system-user string              System account user for use with nats-resolver enabled nats-server. (Default to temporarily generated user)
      --timeout int                     timeout in seconds [1-60] to wait for responses from the server (only applicable to nats-resolver configurations, and applies per operation) (default 1)
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

###### Auto generated by spf13/cobra on 2-Jan-2025
