package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// 上述代码生成了一个自签名证书请求（CSR），其中包括了公钥、主题信息和签名算法等。私钥也被生成并保存到文件中。

// 生成自签名证书：

// 生成自签名证书的过程需要使用之前生成的CSR和私钥。以下是一个示例代码：
func generateCertificate(csrFile, keyFile string) error {
	// Read CSR
	csrPEM, err := os.ReadFile(csrFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}

	// Read private key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Save the self-signed certificate to a file
	certFile, err := os.Create("selfsigned.crt")
	if err != nil {
		return err
	}
	defer certFile.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	certFile.Write(certPEM)

	return nil
}

func main() {
	err := generateCertificate("example.csr", "private.key")
	if err != nil {
		fmt.Println("Error generating certificate:", err)
		return
	}

	fmt.Println("Self-signed certificate generated successfully.")
}
