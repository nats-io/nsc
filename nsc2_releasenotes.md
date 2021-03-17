## NSC 2.2

**WARNING**: This release of NSC is only compatible with [nats-server 2.2 or better](https://github.com/nats-io/nats-server/releases/tag/v2.2.0). The dramatic version increase is to help map compatible versions of `nats-server` and `nsc`.

**NGS Compatibility Notice**: Please continue to use [nsc 0.5.0](https://github.com/nats-io/nsc/releases/tag/0.5.0) to manage your NGS service configurations. An NGS release compatible with `nsc 2.2.0` will be available soon.

### Upgrading and Downgrading NSC

You can easily move between releases by doing `nsc update --version XXX`, where _XXX_ is the release version number. This will update or downgrade `nsc` to the specified version: `nsc upgrade --version 2.2.0`.

### Upgrade Configuration Procedure

The upgrade procedure requires the following steps:

- Upgrade your nats-server(s) to 2.2.0 or better. The nats-server will work correctly with your previous JWT configurations.

- Verify all of your servers are on the same version, if using a [`nats-account-server`](https://docs.nats.io/nats-tools/nas) make sure the version you upgrade to is JWT 2 compliant.

- Upgrade your NSC configurations. Use the `nsc upgrade-jwt` command. You will need the Operator's main identity key to perform the upgrade.

- Redistribute the updated Operator JWT to all of your servers. You can easily export the operator JWT by issuing the command: `nsc describe operator --raw > /tmp/operator.jwt` If your server is configured to a JWT operator file, make sure the name matches. If the JWT is embedded into the server configuration, make sure to copy the contents of the exported operator JWT.

- Restart the nats-server(s). You may want to enable [LDM](https://docs.nats.io/nats-server/nats_admin/lame_duck_mode) on the server(s) to shut down the server(s) in an orderly manner.

### Notable Changes

- [feat] updated pull and push operations to work with nats-based resolvers
- [feat] added `generate --config --nats-resolver` to generate nats resolver configurations
- [feat] added env `NATS_CA` where a root certificate can be specified which then gets referenced by nsc's nats connections
- [feat] changed ANSI tables to ASCII to match other tooling
- [fix] made managed accounts self-save when failing to push to an account server
- [feat] updated revocation commands to allow for "*" as an argument for an account or user key
- [feat] added `import account/user --file` argument to import from a file
- [feat] added `add operator --force` argument to overwrite an existing operator
- [feat] added `jwt describe  --json` to take an argument describing a JSON path in the JWT
- [feat] added the ability to select a signing key when signing a user
- [feat] added ability to sign accounts on managed stores for which the user has the operator key
- [feat] updated to jwt v2
- [feat] added warnings and upgrade procedure when accessing a store that is JWT v1
- [feat] added ability to edit system account
- [feat] added ability to edit JetStream settings
- [feat] added ability to edit description and info url fields to exports
- [feat] added ability to specify account default permissions
- [feat] added support to limit user connections to specific services (connection types)
- [feat] added `generate diagram` to generate a diagram describing the store components
- [feat] added `validate` commands to validate specified objects, including files
- [feat] added `add export --sampling` and `add import --share` to enable latency tracking
- [feat] added `add export --response-threshold` to control the duration a service is allowed to respond
- [feat] added support for wildcard service imports
- [feat] deprecated `to` in favor of `local subject`
- [feat] added ability to specify permissions with a queue (subject + ' ' + queue name) note there's a space separating the subject and the queue name
- [feat] `import account/operator --force` allows importing accounts signed by a different operator
- [feat] added `reissue operator` command which will re-issue the identity of the operator and resign all affected accounts
- [feat] `add operator --generate-signing-key --sys` will generate a signing key with the operator and also generate a system account
- [feat] `edit operator --require-signing-keys` requires accounts to be issued using a signing key
