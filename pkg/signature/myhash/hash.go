package myhash

import (
	"crypto"
	"crypto/rsa"
	msm3 "github.com/gobars/sigstore/pkg/signature/myhash/sm3"
	"hash"
	"io"
	"strconv"
)

// Hash identifies a cryptographic hash function that is implemented in another
// package.
type Hash uint

// HashFunc simply returns the value of h so that Hash implements SignerOpts.
func (h Hash) HashFunc() Hash {
	return h
}

// import
func init() {
	RegisterHash(MD4, crypto.MD4.New)
	RegisterHash(MD5, crypto.MD5.New)
	RegisterHash(SHA1, crypto.SHA1.New)
	RegisterHash(SHA224, crypto.SHA224.New)
	RegisterHash(SHA256, crypto.SHA256.New)
	RegisterHash(SHA384, crypto.SHA384.New)
	RegisterHash(SHA512, crypto.SHA512.New)
	RegisterHash(MD5SHA1, crypto.MD5SHA1.New)
	RegisterHash(RIPEMD160, crypto.RIPEMD160.New)
	RegisterHash(SHA3_224, crypto.SHA3_224.New)
	RegisterHash(SHA3_256, crypto.SHA3_256.New)
	RegisterHash(SHA3_384, crypto.SHA3_384.New)
	RegisterHash(SHA3_512, crypto.SHA3_512.New)
	RegisterHash(SHA512_224, crypto.SHA512_224.New)
	RegisterHash(SHA512_256, crypto.SHA512_256.New)
	RegisterHash(BLAKE2s_256, crypto.BLAKE2s_256.New)
	RegisterHash(BLAKE2b_256, crypto.BLAKE2b_256.New)
	RegisterHash(BLAKE2b_384, crypto.BLAKE2b_384.New)
	RegisterHash(BLAKE2b_512, crypto.BLAKE2b_512.New)
	RegisterHash(SM3, msm3.New)

}

func (h Hash) String() string {
	switch h {
	case MD4:
		return "MD4"
	case MD5:
		return "MD5"
	case SHA1:
		return "SHA-1"
	case SHA224:
		return "SHA-224"
	case SHA256:
		return "SHA-256"
	case SHA384:
		return "SHA-384"
	case SHA512:
		return "SHA-512"
	case MD5SHA1:
		return "MD5+SHA1"
	case RIPEMD160:
		return "RIPEMD-160"
	case SHA3_224:
		return "SHA3-224"
	case SHA3_256:
		return "SHA3-256"
	case SHA3_384:
		return "SHA3-384"
	case SHA3_512:
		return "SHA3-512"
	case SHA512_224:
		return "SHA-512/224"
	case SHA512_256:
		return "SHA-512/256"
	case BLAKE2s_256:
		return "BLAKE2s-256"
	case BLAKE2b_256:
		return "BLAKE2b-256"
	case BLAKE2b_384:
		return "BLAKE2b-384"
	case BLAKE2b_512:
		return "BLAKE2b-512"
	case SM3:
		return "SM3"
	default:
		return "unknown hash value " + strconv.Itoa(int(h))
	}
}

const (
	MD4         Hash = 1 + iota // import golang.org/x/crypto/md4
	MD5                         // import crypto/md5
	SHA1                        // import crypto/sha1
	SHA224                      // import crypto/sha256
	SHA256                      // import crypto/sha256
	SHA384                      // import crypto/sha512
	SHA512                      // import crypto/sha512
	MD5SHA1                     // no implementation; MD5+SHA1 used for TLS RSA
	RIPEMD160                   // import golang.org/x/crypto/ripemd160
	SHA3_224                    // import golang.org/x/crypto/sha3
	SHA3_256                    // import golang.org/x/crypto/sha3
	SHA3_384                    // import golang.org/x/crypto/sha3
	SHA3_512                    // import golang.org/x/crypto/sha3
	SHA512_224                  // import crypto/sha512
	SHA512_256                  // import crypto/sha512
	BLAKE2s_256                 // import golang.org/x/crypto/blake2s
	BLAKE2b_256                 // import golang.org/x/crypto/blake2b
	BLAKE2b_384                 // import golang.org/x/crypto/blake2b
	BLAKE2b_512                 // import golang.org/x/crypto/blake2b
	SM3                         //  import
	maxHash
)

var digestSizes = []uint8{
	MD4:         16,
	MD5:         16,
	SHA1:        20,
	SHA224:      28,
	SHA256:      32,
	SHA384:      48,
	SHA512:      64,
	SHA512_224:  28,
	SHA512_256:  32,
	SHA3_224:    28,
	SHA3_256:    32,
	SHA3_384:    48,
	SHA3_512:    64,
	MD5SHA1:     36,
	RIPEMD160:   20,
	BLAKE2s_256: 32,
	BLAKE2b_256: 32,
	BLAKE2b_384: 48,
	BLAKE2b_512: 64,
	SM3:         32,
}

// SignerOpts contains options for signing with a Signer.
type SignerOpts interface {
	// HashFunc returns an identifier for the hash function used to produce
	// the message passed to Signer.Sign, or else zero to indicate that no
	// hashing was done.
	HashFunc() Hash
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > 0 && h < maxHash {
		return int(digestSizes[h])
	}
	panic("crypto: Size of unknown hash function")
}

var hashes = make([]func() hash.Hash, maxHash)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxHash {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	return h < maxHash && hashes[h] != nil
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
	if h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	hashes[h] = f
}

// Signer is an interface for an opaque private key that can be used for
// signing operations. For example, an RSA key kept in a hardware module.
type Signer interface {
	// Public returns the public key corresponding to the opaque,
	// private key.
	Public() crypto.PublicKey

	// Sign signs digest with the private key, possibly using entropy from
	// rand. For an RSA key, the resulting signature should be either a
	// PKCS #1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
	// key, it should be a DER-serialised, ASN.1 signature structure.
	//
	// Hash implements the SignerOpts interface and, in most cases, one can
	// simply pass in the hash function used as opts. Sign may also attempt
	// to type assert opts to other types in order to obtain algorithm
	// specific values. See the documentation in each package for details.
	//
	// Note that when a signature of a hash of a larger message is needed,
	// the caller is responsible for hashing the larger message and passing
	// the hash (as digest) and the hash function (as opts) to Sign.
	Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)
}

type BjcaPSSOptions struct {
	// SaltLength controls the length of the salt used in the PSS signature. It
	// can either be a positive number of bytes, or one of the special
	// PSSSaltLength constants.
	SaltLength int

	// Hash is the hash function used to generate the message digest. If not
	// zero, it overrides the hash function passed to SignPSS. It's required
	// when using PrivateKey.Sign.
	Hash Hash
}

// HashFunc returns opts.Hash so that PSSOptions implements crypto.SignerOpts.
func (opts *BjcaPSSOptions) HashFunc() Hash {
	return opts.Hash
}

func (opts *BjcaPSSOptions) saltLength() int {
	if opts == nil {
		return rsa.PSSSaltLengthAuto
	}
	return opts.SaltLength
}

// Decrypter is an interface for an opaque private key that can be used for
// asymmetric decryption operations. An example would be an RSA key
// kept in a hardware module.
type Decrypter interface {
	// Public returns the public key corresponding to the opaque,
	// private key.
	Public() crypto.PublicKey

	// Decrypt decrypts msg. The opts argument should be appropriate for
	// the primitive used. See the documentation in each implementation for
	// details.
	Decrypt(rand io.Reader, msg []byte, opts DecrypterOpts) (plaintext []byte, err error)
}

type DecrypterOpts any
