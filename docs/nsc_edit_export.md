## nsc edit export

Edit an export

### Synopsis

Edit an export

```
nsc edit export [flags]
```

### Options

```
  -a, --account string                account name
      --description string            Description for this export
  -h, --help                          help for export
      --info-url string               Link for more info on this export
      --latency string                latency metrics subject (services only)
  -n, --name string                   export name
  -p, --private                       private export - requires an activation to access
      --response-threshold duration   response threshold duration (units ms/s/m/h) (services only)
      --response-type string          response type for the service [Singleton | Stream | Chunked] (services only) (default "Singleton")
      --rm-latency-sampling           remove latency sampling
      --sampling header               latency sampling percentage [1-100] or header - 0 disables it (services only)
  -r, --service                       export type service
  -s, --subject string                subject
```

### Options inherited from parent commands

```
  -i, --interactive          ask questions for various settings
  -K, --private-key string   private key
```

### SEE ALSO

* [nsc edit](nsc_edit.md)	 - Edit assets such as accounts, imports, and users

###### Auto generated by spf13/cobra on 18-Mar-2021
