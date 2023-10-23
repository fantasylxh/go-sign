package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
)

func generateCSR() ([]byte, *rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	subject := pkix.Name{
		CommonName:         "example.com",
		Organization:       []string{"My Organization"},
		OrganizationalUnit: []string{"IT"},
		Locality:           []string{"City"},
		Province:           []string{"State"},
		Country:            []string{"US"},
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return nil, nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, privKey, nil
}

func main() {
	csrPEM, privKey, err := generateCSR()
	if err != nil {
		fmt.Println("Error generating CSR:", err)
		return
	}

	csrFile, err := os.Create("example.csr")
	if err != nil {
		fmt.Println("Error creating CSR file:", err)
		return
	}
	defer csrFile.Close()
	csrFile.Write(csrPEM)

	// Optionally, you can save the private key
	keyFile, err := os.Create("private.key")
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		return
	}
	defer keyFile.Close()
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	keyFile.Write(keyPEM)

	fmt.Println("CSR and private key generated successfully.")
}
