package sm2

import (
	"crypto"
	"github.com/gobars/sigstore/pkg/signature/myhash"
	"io"
)

func SignPSS(rand io.Reader, priv *crypto.PrivateKey, hash myhash.Hash, digest []byte) ([]byte, error) {
	return nil, nil
}
