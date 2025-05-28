package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smallstep/certinfo"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	_ "go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/tpm/tss2"
)

func main() {
	var (
		name             string
		keyType          string
		clientCert       string
		device           string
		storageDirectory string
		url              string
		forceTSS2        bool
		trustedRootsFile string
		err              error
		verbose          bool
	)

	flag.StringVar(&name, "key", "", "name or path of the key to use (defaults to generating a new one)")
	flag.StringVar(&keyType, "kty", "RSA", "key type (RSA or EC)")
	flag.StringVar(&clientCert, "cert", "", "path to the certificate to use (defaults to automatically generating one)")
	flag.StringVar(&device, "device", "", "TPM device name to use (defaults to automatic detection)")
	flag.StringVar(&storageDirectory, "storage-directory", filepath.Join(".", ".tpmkeys"), "storage directory to use")
	flag.BoolVar(&forceTSS2, "tss2", false, "force (re)load key using TSS2 format")
	flag.StringVar(&url, "url", "https://certauth.cryptomix.com:443", "URL to request") // another: https://certauth.idrix.fr:443
	flag.StringVar(&trustedRootsFile, "roots", "", "path to file with (additional) trusted root CA certificates (defaults to system trust store)")
	flag.BoolVar(&verbose, "verbose", false, "more (debug) output")
	flag.Parse()

	t, err := tpm.New(
		tpm.WithDeviceName(device),
		tpm.WithStore(storage.NewDirstore(storageDirectory)),
	)
	fatalIf(err)

	// determine which TPM key to use. If key is a file, try reading it as a TSS2
	// private key, and use that as the signer. If the name is a single path part,
	// assume it's a literal name for a TPMKMS key. If name is empty, generate a
	// random name, and create the key in the TPMKMS.
	ctx := context.Background()
	var signer crypto.Signer
	var certChain []*x509.Certificate
	_, statErr := os.Stat(name)
	keyFileExists := statErr == nil
	switch {
	case keyFileExists:
		log.Println("reading TSS2 key from file")
		data, err := os.ReadFile(name)
		fatalIf(err)
		p, _ := pem.Decode(data) // ignoring rest
		if p == nil {
			fatalWith("no PEM data found")
		}
		if p.Type != "TSS2 PRIVATE KEY" {
			fatalWith("not a TSS2 Private Key PEM")
		}
		log.Println("parsing TSS2 key")
		tss2Key, err := tss2.ParsePrivateKey(p.Bytes)
		fatalIf(err)
		if verbose {
			b, err := tss2Key.EncodeToMemory()
			fatalIf(err)
			log.Println("parsed TSS2 key:")
			fmt.Println(string(b))
		}
		// create TSS2 signer by "attaching" TPM instance
		signer, err = tpm.CreateTSS2Signer(ctx, t, tss2Key)
		fatalIf(err)
	default:
		log.Println("using TPM key from TPMKMS")
		// process the name; don't allow filename(-like) names for now
		l := filepath.SplitList(name)
		switch len(l) {
		case 0:
			name, err = randutil.Hex(6)
			fatalIf(err)
			log.Printf("generated new key name %q\n", name)
		case 1:
			if filepath.Ext(name) != "" {
				fatalWith(fmt.Sprintf("can't use separator in key name %q", name))
			}
		default:
			fatalWith(fmt.Sprintf("too many parts in key name %q", name))
		}

		k, err := kms.New(ctx, apiv1.Options{
			Type: apiv1.TPMKMS,
			URI:  fmt.Sprintf("tpmkms:storage-directory=%s;device=%s", storageDirectory, device),
		})
		fatalIf(err)

		keyName := fmt.Sprintf("tpmkms:name=%s", name)
		if _, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
			Name: keyName,
		}); err != nil {
			if !errors.Is(err, tpm.ErrExists) {
				log.Printf("key %q does not exist in TPMKMS storage %q; creating new one\n", name, storageDirectory)
				signatureAlgorithm := apiv1.SHA256WithRSA
				bits := 2048
				if strings.HasPrefix(strings.ToUpper(keyType), "EC") {
					signatureAlgorithm = apiv1.ECDSAWithSHA256
					bits = 0
				}
				_, err := k.CreateKey(&apiv1.CreateKeyRequest{
					Name:               keyName,
					SignatureAlgorithm: signatureAlgorithm,
					Bits:               bits,
				})
				fatalIf(err)
			}
		}
		signer, err = k.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: keyName,
		})
		fatalIf(err)

		if kc, ok := k.(apiv1.CertificateChainManager); ok {
			chain, err := kc.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
				Name: keyName,
			})
			if err == nil {
				certChain = chain
			}
		}

		if forceTSS2 {
			log.Println("transforming TPM key backed by TPMKMS to TSS2 key")
			tpmKey, err := t.GetKey(ctx, name)
			fatalIf(err)
			tss2Key, err := tpmKey.ToTSS2(ctx)
			fatalIf(err)
			signer, err = tpm.CreateTSS2Signer(ctx, t, tss2Key)
			fatalIf(err)
			if verbose {
				b, err := tss2Key.EncodeToMemory()
				fatalIf(err)
				log.Println("encoded TSS2 key:")
				fmt.Println(string(b))
			}
		}
	}

	// a certificate chain can be available, if loaded from the TPMKMS, but if
	// there's no certificate (chain) yet, try to create one either from the client
	// certificate file or using a temporary CA
	if len(certChain) == 0 {
		if clientCert == "" {
			log.Println("generating new client certificate for TPM key")
			ca, err := minica.New(
				minica.WithName("TPM Test"),
			)
			fatalIf(err)

			template := &x509.Certificate{
				PublicKey: signer.Public(),
				Subject: pkix.Name{
					CommonName: "Test Client",
				},
				NotBefore: time.Now().Add(-1 * time.Minute),
				NotAfter:  time.Now().Add(60 * time.Minute),
			}

			cert, err := ca.Sign(template)
			fatalIf(err)

			certChain = []*x509.Certificate{cert, ca.Intermediate}
		} else {
			log.Printf("reading client certificate (chain) for TPM key from %q\n", clientCert)
			certChain, err = pemutil.ReadCertificateBundle(clientCert)
			fatalIf(err)
		}
	}

	if len(certChain) == 0 {
		fatalWith("no client certificate (chain) available")
	}

	if verbose {
		log.Println("client certificate chain PEM:")
		for _, c := range certChain {
			p, err := pemutil.Serialize(c)
			fatalIf(err)
			b := pem.EncodeToMemory(p)
			fmt.Print(string(b))
		}
		fmt.Println()
	}

	cert := certChain[0]
	txt, err := certinfo.CertificateText(cert)
	fatalIf(err)

	log.Println("client certificate:")
	fmt.Println(txt)

	// process trusted roots
	trustedRoots, err := x509.SystemCertPool()
	fatalIf(err)

	if trustedRootsFile != "" {
		bundle, err := pemutil.ReadCertificateBundle(trustedRootsFile)
		fatalIf(err)
		for _, root := range bundle {
			trustedRoots.AddCert(root)
		}
	}

	certificates := make([][]byte, len(certChain))
	for i, c := range certChain {
		certificates[i] = c.Raw
	}

	// prepare HTTP client for mTLS
	client := http.Client{
		Timeout: time.Minute * 3,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: trustedRoots,
				Certificates: []tls.Certificate{
					{
						Certificate: certificates,
						PrivateKey:  signer,
						Leaf:        cert,
					},
				},
			},
		},
	}

	// send HTTP request
	log.Printf("sending HTTP request to %q\n", url)
	r, err := client.Get(url)
	fatalIf(err)
	defer r.Body.Close()

	if r.StatusCode >= 300 {
		fatalWith(fmt.Sprintf("got HTTP status %d", r.StatusCode))
	}

	body, err := io.ReadAll(r.Body)
	fatalIf(err)

	log.Printf("got HTTP response from %q:\n", url)
	fmt.Println(string(body))
}

func fatalWith(msg string) {
	log.Fatal(errors.New(msg))
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
