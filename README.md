# tpmkms-mtls-example

An example application showcasing parts of [TPMKMS](https://github.com/smallstep/crypto/tree/master/kms/tpmkms), [tpm](https://github.com/smallstep/crypto/tree/master/tpm) and [tss2](https://github.com/smallstep/crypto/tree/master/tpm/tss2) usage for mTLS.

An mTLS request to https://certauth.cryptomix.com is made using a private key backed by a TPM, and the results are printed afterwards.

## Examples

```console
# use (or generate) "my-key", and generate a temporary certificate
go run main.go --key my-key

# use (or generate) "my-key" and use provided certificate (chain)
go run main.go --key my-key --cert client.pem

# use (or generate) "my-key", force TSS2 (re)load of the key, and generate a temporary certificate
go run main.go --key my-key --tss2

# use a previously created TSS2 key file
go run main.go --key test.tss2.pem

# use (or generate) "my-key", generate a temporary certificate, and print verbose output
go run main.go --key my-key --verbose
```

## Usage

```console
Usage of tpmkms-mtls-example:
  -cert string
    	path to the certificate to use (defaults to automatically generating one)
  -device string
    	TPM device name to use (defaults to automatic detection)
  -key string
    	name or path of the key to use (defaults to generating a new one)
  -kty string
    	key type (RSA or EC) (default "RSA")
  -roots string
    	path to file with (additional) trusted root CA certificates (defaults to system trust store)
  -storage-directory string
    	storage directory to use (default ".tpmkeys")
  -tss2
    	force (re)load key using TSS2 format
  -url string
    	URL to request (default "https://certauth.cryptomix.com:443")
  -verbose
    	more (debug) output
```