## nsc edit user

Edit an user

### Synopsis

# Edit permissions so that the user can publish and/or subscribe to the specified subjects or wildcards:
nsc edit user --name <n> --allow-pubsub <subject>,...
nsc edit user --name <n> --allow-pub <subject>,...
nsc edit user --name <n> --allow-sub <subject>,...

# Set permissions so that the user cannot publish nor subscribe to the specified subjects or wildcards:
nsc edit user --name <n> --deny-pubsub <subject>,...
nsc edit user --name <n> --deny-pub <subject>,...
nsc edit user --name <n> --deny-sub <subject>,...

# Set subscribe permissions with queue names (separated from subject by space)
# When added this way, the corresponding remove command needs to be presented with the exact same string
nsc edit user --name <n> --deny-sub "<subject> <queue>,..."
nsc edit user --name <n> --allow-sub "<subject> <queue>,..."

# Remove a previously set permissions
nsc edit user --name <n> --rm <subject>,...

# To dynamically allow publishing to reply subjects, this works well for service responders:
nsc edit user --name <n> --allow-pub-response

# A permission to publish a response can be removed after a duration from when
# the message was received:
nsc edit user --name <n> --allow-pub-response --response-ttl 5s

# If the service publishes multiple response messages, you can specify:
nsc edit user --name <n> --allow-pub-response=5
# See 'nsc edit export --response-type --help' to enable multiple
# responses between accounts.

# To remove response settings:
nsc edit user --name <n> --rm-response-perms


```
nsc edit user [flags]
```

### Options

```
  -a, --account string               account name
      --allow-pub strings            add publish permissions - comma separated list or option can be specified multiple times
      --allow-pub-response int[=1]   permissions to limit how often a client can publish to reply subjects [with an optional count, --allow-pub-response=n] (global)
      --allow-pubsub strings         add publish and subscribe permissions - comma separated list or option can be specified multiple times
      --allow-sub strings            add subscribe permissions - comma separated list or option can be specified multiple times
      --bearer                       no connect challenge required for user
      --conn-type strings            set allowed connection types: LEAFNODE MQTT STANDARD WEBSOCKET LEAFNODE_WS MQTT_WS IN_PROCESS - comma separated list or option can be specified multiple times
      --data number                  set maximum data in bytes for the user (-1 is unlimited) (default -1)
      --deny-pub strings             add deny publish permissions - comma separated list or option can be specified multiple times
      --deny-pubsub strings          add deny publish and subscribe permissions - comma separated list or option can be specified multiple times
      --deny-sub strings             add deny subscribe permissions - comma separated list or option can be specified multiple times
      --expiry string                valid until ('0' is always, '2M' is two months) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)
  -h, --help                         help for user
      --locale time-locale           set the locale with which time values are interpreted
  -n, --name string                  user name
      --payload number               set maximum message payload in bytes for the account (-1 is unlimited) (default -1)
      --response-ttl string          the amount of time the permissions is valid (global) - [#ms(millis) | #s(econds) | m(inutes) | h(ours)] - Default is no time limit.
      --rm strings                   remove publish/subscribe and deny permissions - comma separated list or option can be specified multiple times
      --rm-conn-type strings         remove connection types - comma separated list or option can be specified multiple times
      --rm-response-perms            remove response settings from permissions
      --rm-source-network strings    remove source network for connection - comma separated list or option can be specified multiple times
      --rm-tag strings               remove tag - comma separated list or option can be specified multiple times
      --rm-time strings              remove start-end time by start time "hh:mm:ss" (option can be specified multiple times)
      --source-network strings       add source network for connection - comma separated list or option can be specified multiple times
      --start string                 valid from ('0' is always, '3d' is three days) - yyyy-mm-dd, #m(inutes), #h(ours), #d(ays), #w(eeks), #M(onths), #y(ears)
      --subs int                     set maximum number of subscriptions (-1 is unlimited) (default -1)
      --tag strings                  add tags for user - comma separated list or option can be specified multiple times
      --time time-ranges             add start-end time range of the form "hh:mm:ss-hh:mm:ss" (option can be specified multiple times) (default [])
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
