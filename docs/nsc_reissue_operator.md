## nsc reissue operator

Re-issues the operator with a new identity and re-signs affected accounts

### Synopsis

Re-issues the operator with a new identity and re-signs affected accounts

```
nsc reissue operator [flags]
```

### Examples

```
nsc reissue operator
```

### Options

```
      --convert-to-signing-key   turn operator identity key into signing key (avoids account re-signing)
  -h, --help                     help for operator
  -n, --name string              operator name
```

### Options inherited from parent commands

```
      --config-dir string     nsc config directory
      --data-dir string       nsc data store directory
  -i, --interactive           ask questions for various settings
      --keystore-dir string   nsc keystore directory
  -K, --private-key string    Key used to sign. Can be specified as role (where applicable),
                              public key (private portion is retrieved)
                              or file path to a private key or private key 
```

### SEE ALSO

* [nsc reissue](nsc_reissue.md)	 - Re-issue objects with a new identity key

###### Auto generated by spf13/cobra on 25-Feb-2022
