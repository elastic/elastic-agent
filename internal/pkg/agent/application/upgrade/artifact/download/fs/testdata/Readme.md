# Generating a key, exporting the public key, signing a file and verifying it

Full docs: https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html

## Generate a key

```shell
gpg --no-default-keyring --keyring ./some-file-to-be-the-key-ring --quick-generate-key atest  rsa2048 default none
```
Where:
 - `--no-default-keyring`: do not use your keyring
 - `--keyring ./some-file-to-be-the-key-ring`: keyring to use, as the file do not exist, it'll create it
 - `--quick-generate-key`: quick generate the key
 - `atest`: user-id, a.k.a the key identifier
 - `rsa2048`: algorithm to use
 - `default`: "usage" for the key. Just use default
 - `none`: key expiration


## Export the public key
```shell
gpg --no-default-keyring --keyring ./some-file-to-be-the-key-ring --armor --output public-key.pgp --export atest
```
Where:
- `--no-default-keyring`: do not use your keyring
 - `--keyring ./some-file-to-be-the-key-ring`: the keyring to use, created in the previous step
 - `--armor`: create ASCII armoured output. Otherwise, it's a binary format
 - `--output public-key.pgp`: the output file
 - `--export`: export the public key
 - `atest`: the key identifier

## Sing the file
```shell
gpg --no-default-keyring --keyring ./some-file-to-be-the-key-ring -a -o elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc --detach-sign elastic-agent-8.0.0-darwin-x86_64.tar.gz
```

Where:
 - `-a -o`: --armored, --output
 - `elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc`: the output file
 - `--detach-sign`: generate a separated file for signature
 - `elastic-agent-8.0.0-darwin-x86_64.tar.gz`: the file to sign



## Verify the file

### Import the public key
```shell
gpg --no-default-keyring --keyring ./new-keyring --import public-key.pgp
```
Where:
 - `--import`: import a key
 - `public-key.pgp`: the key to import

### Verify the signature using the imported key
```shell
gpg --no-default-keyring --keyring ./new-keyring --verify elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc
```
Where:
 - `--verify`: verify a signature
 - `elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc`: the detached signature file. It'll assume the file to be verified is `elastic-agent-8.0.0-darwin-x86_64.tar.gz`
