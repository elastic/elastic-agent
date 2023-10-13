# Signing Elastic Agent artifacts

This doc covers generating a key, exporting the public key, signing a file and verifying it using GPG as well as pure Go.

Full GPG docs: https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html


## Go

```go
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	dir, err := os.MkdirTemp(os.TempDir(), "pgp-")
	NoError(err, "could not create directory to save the files to")

	key := filepath.Join(dir, "key")
	keyPub := filepath.Join(dir, "key.pub")
	asc := filepath.Join(dir, "plaindata.asc")

	fmt.Printf("Writing files to %q\n", dir)

	data := []byte("some data")
	plaindata := filepath.Join(dir, "plaindata")
	err = os.WriteFile(plaindata, data, 0o600)
	NoError(err, "could not write plain data file")

	fmt.Printf("wrote %q\n", plaindata)

	// Create files
	fKeyPub, err := os.OpenFile(
		keyPub,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	NoError(err, "could not create %q file", keyPub)
	defer func() {
		if err := fKeyPub.Close(); err != nil {
			fmt.Printf("failed closing %q\n", fKeyPub.Name())
		}
		fmt.Printf("wrote %q\n", fKeyPub.Name())
	}()

	fKey, err := os.OpenFile(
		key,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	NoError(err, "could not create %q file", key)
	defer func() {
		if err := fKey.Close(); err != nil {
			fmt.Printf("failed closing %q\n", fKey.Name())
		}
		fmt.Printf("wrote %q\n", fKey.Name())
	}()

	fasc, err := os.OpenFile(
		asc,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	NoError(err, "could not create %q file", asc)
	defer func() {
		if err := fasc.Close(); err != nil {
			fmt.Printf("failed closing %q\n", fasc.Name())
		}
		fmt.Printf("wrote %q\n", fasc.Name())
	}()

	// Generate PGP key
	entity, err := openpgp.NewEntity("someKeyName", "", "", nil)

	// Create an ASCII armored encoder to serialize the private key
	wPubKey, err := armor.Encode(fKeyPub, openpgp.PublicKeyType, nil)
	NoError(err, "could not create PGP ASCII Armor encoder for public key")
	defer func() {
		err := wPubKey.Close()
		if err != nil {
			fmt.Println("failed closing private key writer")
		}
	}()

	// Writes the public key to the io.Writer passed to armor.Encode.
	// Use entity.SerializePrivate if you need the private key.
	err = entity.Serialize(wPubKey)
	NoError(err, "could not serialize the public key")

	// Create an ASCII armored encoder to serialize the private key
	wPrivKey, err := armor.Encode(fKey, openpgp.PrivateKeyType, nil)
	NoError(err, "could not create PGP ASCII Armor encoder for private key")
	defer func() {
		err := wPrivKey.Close()
		if err != nil {
			fmt.Println("failed closing private key writer")
		}
	}()

	// Writes the private key to the io.Writer passed to armor.Encode.
	// Use entity.SerializePrivate if you need the private key.
	err = entity.SerializePrivate(wPrivKey, nil)
	NoError(err, "could not serialize the private key")

	// Sign data and write the detached signature to fasc
	err = openpgp.ArmoredDetachSign(fasc, entity, bytes.NewReader(data), nil)
	NoError(err, "failed signing date")
}

func NoError(err error, msg string, args ...any) {
	if err != nil {
		panic(fmt.Sprintf(msg+": %v", append(args, err)))
	}
}
```

## GPG
### Generate a key

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


### Export the public key
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

### Sing the file
```shell
gpg --no-default-keyring --keyring ./some-file-to-be-the-key-ring -a -o elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc --detach-sign elastic-agent-8.0.0-darwin-x86_64.tar.gz
```

Where:
 - `-a -o`: --armored, --output
 - `elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc`: the output file
 - `--detach-sign`: generate a separated file for signature
 - `elastic-agent-8.0.0-darwin-x86_64.tar.gz`: the file to sign



### Verify the file

#### Import the public key
```shell
gpg --no-default-keyring --keyring ./new-keyring --import public-key.pgp
```
Where:
 - `--import`: import a key
 - `public-key.pgp`: the key to import

#### Verify the signature using the imported key
```shell
gpg --no-default-keyring --keyring ./new-keyring --verify elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc
```
Where:
 - `--verify`: verify a signature
 - `elastic-agent-8.0.0-darwin-x86_64.tar.gz.asc`: the detached signature file. It'll assume the file to be verified is `elastic-agent-8.0.0-darwin-x86_64.tar.gz`
