package signature

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/gobars/sigstore/pkg/signature/myhash"
	"github.com/gobars/sigstore/pkg/signature/sm2"
	"io"

	"github.com/gobars/sigstore/pkg/signature/options"
)

// checked on LoadSigner, LoadVerifier and SignMessage
var sm2SupportedHashFuncs = []myhash.Hash{
	myhash.SM3,
}

// checked on VerifySignature. Supports SHA1 verification.
var sm2SupportedVerifyHashFuncs = []myhash.Hash{
	myhash.SM3,
}

// SM2Signer is a signature.Signer that uses an Elliptic Curve DSA algorithm
type SM2Signer struct {
	hashFunc myhash.Hash
	priv     *sm2.PrivateKey
}

// LoadSM2Signer calculates signatures using the specified private key and hash algorithm.
//
// hf must not be crypto.Hash(0).
func LoadSM2Signer(priv *sm2.PrivateKey, hf myhash.Hash) (*SM2Signer, error) {
	if priv == nil {
		return nil, errors.New("invalid Sm2 private key specified")
	}

	if !isSupportedAlg(hf, sm2SupportedHashFuncs) {
		return nil, errors.New("invalid hash function specified")
	}

	return &SM2Signer{
		priv:     priv,
		hashFunc: hf,
	}, nil
}

// SignMessage signs the provided message. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the ECDSASigner was created.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithRand()
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (e SM2Signer) SignMessage(message io.Reader, opts ...SignOption) ([]byte, error) {
	var cryptoSignerOpts myhash.SignerOpts = e.hashFunc
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&cryptoSignerOpts)
	}
	rand := selectRandFromOpts(opts...)

	return e.priv.SignReader(rand, message, cryptoSignerOpts)

}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (e SM2Signer) Public() crypto.PublicKey {
	if e.priv == nil {
		return nil
	}

	return e.priv.Public()
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (e SM2Signer) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return e.Public(), nil
}

// Sign computes the signature for the specified digest. If a source of entropy is
// given in rand, it will be used instead of the default value (rand.Reader from crypto/rand).
//
// If opts are specified, the hash function in opts.Hash should be the one used to compute
// digest. If opts are not specified, the value provided when the signer was created will be used instead.
func (e SM2Signer) Sign(rand io.Reader, digest []byte, opts myhash.SignerOpts) ([]byte, error) {
	ecdsaOpts := []SignOption{options.WithDigest(digest), options.WithRand(rand)}
	if opts != nil {
		ecdsaOpts = append(ecdsaOpts, options.WithCryptoSignerOpts(opts))
	}

	return e.SignMessage(nil, ecdsaOpts...)
}

// SM2Verifier is a signature.Verifier that uses an Elliptic Curve DSA algorithm
type SM2Verifier struct {
	publicKey *sm2.PublicKey
	hashFunc  myhash.Hash
}

// LoadSM2Verifier returns a Verifier that verifies signatures using the specified
// ECDSA public key and hash algorithm.
//
// hf must not be crypto.Hash(0).
func LoadSM2Verifier(pub *sm2.PublicKey, hashFunc myhash.Hash) (*SM2Verifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ECDSA public key specified")
	}

	if !isSupportedAlg(hashFunc, sm2SupportedHashFuncs) {
		return nil, errors.New("invalid hash function specified")
	}

	return &SM2Verifier{
		publicKey: pub,
		hashFunc:  hashFunc,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (e SM2Verifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return e.publicKey, nil
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the ECDSAVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (e SM2Verifier) VerifySignature(signature, message io.Reader, opts ...VerifyOption) error {
	if e.publicKey == nil {
		return errors.New("no public key set for ECDSAVerifier")
	}

	/*

		digest, _, err := ComputeDigestForVerifying(message, e.hashFunc, sm2SupportedVerifyHashFuncs, opts...)
		if err != nil {
			return err
		} */

	hashedWith := e.hashFunc
	if !isSupportedAlg(hashedWith, sm2SupportedVerifyHashFuncs) {
		return fmt.Errorf("unsupported hash algorithm: %q not in %v", hashedWith.String(), sm2SupportedVerifyHashFuncs)
	}

	rawMessage, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	if signature == nil {
		return errors.New("nil signature passed to VerifySignature")
	}

	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	// Without this check, VerifyASN1 panics on an invalid key.
	if !e.publicKey.Curve.IsOnCurve(e.publicKey.X, e.publicKey.Y) {
		return fmt.Errorf("invalid ECDSA public key for %s", e.publicKey.Params().Name)
	}

	if !e.publicKey.Verify(rawMessage, sigBytes) {
		return errors.New("invalid signature when validating ASN.1 encoded signature")
	}

	return nil
}

// ECDSASignerVerifier is a signature.SignerVerifier that uses an Elliptic Curve DSA algorithm
type SM2SignerVerifier struct {
	*SM2Signer
	*SM2Verifier
}

// LoadECDSASignerVerifier creates a combined signer and verifier. This is a convenience object
// that simply wraps an instance of ECDSASigner and ECDSAVerifier.
func LoadSM2SignerVerifier(priv *sm2.PrivateKey, hf myhash.Hash) (*SM2SignerVerifier, error) {
	signer, err := LoadSM2Signer(priv, hf)
	if err != nil {
		return nil, fmt.Errorf("initializing signer: %w", err)
	}
	verifier, err := LoadSM2Verifier(&priv.PublicKey, hf)
	if err != nil {
		return nil, fmt.Errorf("initializing verifier: %w", err)
	}

	return &SM2SignerVerifier{
		SM2Signer:   signer,
		SM2Verifier: verifier,
	}, nil
}

// NewDefaultSM2SignerVerifier creates a combined signer and verifier using ECDSA.
//
// This creates a new ECDSA key using the P-256 curve and uses the SHA256 hashing algorithm.
func NewDefaultSM2SignerVerifier() (*SM2SignerVerifier, *sm2.PrivateKey, error) {
	return NewSM2SignerVerifier(rand.Reader, myhash.SM3)
}

// NewSM2SignerVerifier creates a combined signer and verifier using ECDSA.
//
// This creates a new SM2 key using the specified elliptic curve, entropy source, and hashing function.
func NewSM2SignerVerifier(rand io.Reader, hashFunc myhash.Hash) (*SM2SignerVerifier, *sm2.PrivateKey, error) {
	priv, err := sm2.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadSM2SignerVerifier(priv, hashFunc)
	if err != nil {
		return nil, nil, err
	}

	return sv, priv, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (e SM2SignerVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return e.publicKey, nil
}
