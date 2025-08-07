package controller

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"go.mozilla.org/pkcs7"
)

func (r *OCPCertificateApplierReconciler) getCertificate(certPath string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func (r *OCPCertificateApplierReconciler) wrapBase64(s string, lineLength int) string {
	var builder strings.Builder
	for i := 0; i < len(s); i += lineLength {
		end := i + lineLength
		if end > len(s) {
			end = len(s)
		}
		builder.WriteString(s[i:end])
		builder.WriteString("\n")
	}
	return builder.String()
}

func (r *OCPCertificateApplierReconciler) encryptKey(key []byte) ([]byte, error) {

	certFile := "/repo/misc/certs/cert.pem"

	cert, err := r.getCertificate(certFile)
	if err != nil {
		return nil, err
	}

	encrypted, err := pkcs7.Encrypt(key, []*x509.Certificate{cert})
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)

	wrappedEncoded := r.wrapBase64(encoded, 64)

	var buf bytes.Buffer
	buf.WriteString("MIME-Version: 1.0\n")
	buf.WriteString("Content-Disposition: attachment; filename=\"smime.p7m\"\n")
	buf.WriteString("Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\n")
	buf.WriteString("Content-Transfer-Encoding: base64\n\n")
	buf.WriteString(wrappedEncoded)
	buf.WriteString("\n")

	return buf.Bytes(), nil
}
