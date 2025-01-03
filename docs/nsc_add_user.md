## nsc add user

Add an user to the account

```
nsc add user [flags]
```

### Examples

```
# Add user with a previously generated public key:
nsc add user --name <n> --public-key <nkey>
# Note: that unless you specify the seed, the key won't be stored in the keyring.'

# Set permissions so that the user can publish and/or subscribe to the specified subjects or wildcards:
nsc add user --name <n> --allow-pubsub <subject>,...
nsc add user --name <n> --allow-pub <subject>,...
nsc add user --name <n> --allow-sub <subject>,...

# Set permissions so that the user cannot publish nor subscribe to the specified subjects or wildcards:
nsc add user --name <n> --deny-pubsub <subject>,...
nsc add user --name <n> --deny-pub <subject>,...
nsc add user --name <n> --deny-sub <subject>,...

# Set subscribe permissions with queue names (separated from subject by space)
# When added this way, the corresponding remove command needs to be presented with the exact same string
nsc add user --name <n> --deny-sub "<subject> <queue>,..."
nsc add user --name <n> --allow-sub "<subject> <queue>,..."

# To dynamically allow publishing to reply subjects, this works well for service responders:
nsc add user --name <n> --allow-pub-response

# A permission to publish a response can be removed after a duration from when 
# the message was received:
nsc add user --name <n> --allow-pub-response --response-ttl 5s

# If the service publishes multiple response messages, you can specify:
nsc add user --name <n> --allow-pub-response=5
# See 'nsc edit export --response-type --help' to enable multiple
# responses between accounts

```

### Options

```
  -a, --account string               account name
      --allow-pub strings            add publish permissions - comma separated list or option can be specified multiple times
      --allow-pub-response int[=1]   permissions to limit how often a client can publish to reply subjects [with an optional count, --allow-pub-response=n] (global)
      --allow-pubsub strings         add publish and subscribe permissions - comma separated list or option can be specified multiple times
      --allow-sub strings            add subscribe permissions - comma separated list or option can be specified multiple times
      --bearer                       no connect challenge required for user
      --deny-pub strings             add deny publish permissions - comma separated list or option can be specified multiple times
      --deny-pubsub strings          add deny publish and subscribe permissions - comma separated list or option can be specified multiple times
      --deny-sub strings             add deny subscribe permissions - comma separated list or option can be specified multiple times
      --expiry string                valid until ('0' is always, '2M' is two months) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)
  -h, --help                         help for user
  -n, --name string                  name to assign the user
  -k, --public-key string            public key identifying the user
      --response-ttl string          the amount of time the permissions is valid (global) - [#ms(millis) | #s(econds) | m(inutes) | h(ours)] - Default is no time limit.
      --source-network strings       source network for connection - comma separated list or option can be specified multiple times
      --start string                 valid from ('0' is always, '3d' is three days) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)
      --tag strings                  tags for user - comma separated list or option can be specified multiple times
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

* [nsc add](nsc_add.md)	 - Add assets such as accounts, imports, users

###### Auto generated by spf13/cobra on 2-Jan-2025
