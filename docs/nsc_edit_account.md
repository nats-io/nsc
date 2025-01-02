## nsc edit account

Edit an account

```
nsc edit account [flags]
```

### Options

```
      --allow-pub strings               add publish default permissions - comma separated list or option can be specified multiple times
      --allow-pub-response int[=1]      default permissions to limit how often a client can publish to reply subjects [with an optional count, --allow-pub-response=n] (global)
      --allow-pubsub strings            add publish and subscribe default permissions - comma separated list or option can be specified multiple times
      --allow-sub strings               add subscribe default permissions - comma separated list or option can be specified multiple times
      --conns number                    set maximum active connections for the account (-1 is unlimited) (default -1)
      --data number                     set maximum data in bytes for the account (-1 is unlimited) (default -1)
      --deny-pub strings                add deny publish default permissions - comma separated list or option can be specified multiple times
      --deny-pubsub strings             add deny publish and subscribe default permissions - comma separated list or option can be specified multiple times
      --deny-sub strings                add deny subscribe default permissions - comma separated list or option can be specified multiple times
      --description string              Description for this account
      --disallow-bearer                 require user jwt to not be bearer token
      --expiry string                   valid until ('0' is always, '2M' is two months) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)
      --exports number                  set maximum number of exports for the account (-1 is unlimited) (default -1)
  -h, --help                            help for account
      --imports number                  set maximum number of imports for the account (-1 is unlimited) (default -1)
      --info-url string                 Link for more info on this account
      --js-consumer number              JetStream: set maximum consumer for the account (-1 is unlimited) (default -1)
      --js-disable                      disables all JetStream limits in the account by deleting any limits
      --js-disk-storage number          JetStream: set maximum disk storage in bytes for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)
      --js-enable int                   enables JetStream for the specified tier (default -1)
      --js-max-ack-pending number       JetStream: set number of maximum acks that can be pending for a consumer in the account (default -1)
      --js-max-bytes-required           JetStream: set whether max stream is required when creating a stream
      --js-max-disk-stream number       JetStream: set maximum size of a disk stream for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib) (default -1)
      --js-max-mem-stream number        JetStream: set maximum size of a memory stream for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib) (default -1)
      --js-mem-storage number           JetStream: set maximum memory storage in bytes for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)
      --js-streams number               JetStream: set maximum streams for the account (-1 is unlimited) (default -1)
      --js-tier int                     JetStream: replication tier (0 creates a configuration that applies to all assets) 
      --leaf-conns number               set maximum active leaf node connections for the account (-1 is unlimited)
  -n, --name string                     account to edit
      --payload number                  set maximum message payload in bytes for the account (-1 is unlimited) (default -1)
      --response-ttl string             the amount of time the default permissions is valid (global) - [#ms(millis) | #s(econds) | m(inutes) | h(ours)] - Default is no time limit.
      --rm strings                      remove publish/subscribe and deny default permissions - comma separated list or option can be specified multiple times
      --rm-js-tier int                  JetStream: remove replication limits for the specified tier (0 is the global tier) this flag is exclusive of all other js flags (default -1)
      --rm-response-perms               remove response settings from default permissions
      --rm-sk strings                   remove signing key - comma separated list or option can be specified multiple times
      --rm-tag strings                  remove tag - comma separated list or option can be specified multiple times
      --sk strings                      signing key or keypath or the value "generate" to generate a key pair on the fly - comma separated list or option can be specified multiple times
      --start string                    valid from ('0' is always, '3d' is three days) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)
      --subscriptions number            set maximum subscription for the account (-1 is unlimited) (default -1)
      --tag strings                     add tags for user - comma separated list or option can be specified multiple times
      --trace-context-sampling number   set the trace context sampling rate (1-100) - 0 default is 100
      --trace-context-subject string    sets the subject where w3c trace context information is sent. Set to "" to disable (default "trace.messages")
      --wildcard-exports                exports can contain wildcards (default true)
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

* [nsc edit](nsc_edit.md)	 - Edit assets such as accounts, imports, and users

###### Auto generated by spf13/cobra on 2-Jan-2025
