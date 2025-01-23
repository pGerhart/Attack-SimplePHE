package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

	phe "github.com/VirgilSecurity/virgil-phe-go"
	"github.com/VirgilSecurity/virgil-phe-go/swu"

	"github.com/pkg/errors"
)

var (
	randReader = rand.Reader
	Curve      = elliptic.P256()
	CurveG     = new(phe.Point).ScalarBaseMultInt(new(big.Int).SetUint64(1)).Marshal()
	Gf         = swu.GF{P: Curve.Params().N}

	//domains
	commonPrefix     = []byte{0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45} //VRGLPHE
	Dhc0             = append(commonPrefix, 0x31)
	Dhc1             = append(commonPrefix, 0x32)
	Dhs0             = append(commonPrefix, 0x33)
	Dhs1             = append(commonPrefix, 0x34)
	ProofOk          = append(commonPrefix, 0x35)
	ProofError       = append(commonPrefix, 0x36)
	encrypt          = append(commonPrefix, 0x37)
	kdfInfoZ         = append(commonPrefix, 0x38)
	kdfInfoClientKey = append(commonPrefix, 0x39)
)

const (
	pheNonceLen     = 32
	pheClientKeyLen = 32
	symKeyLen       = 32
	symSaltLen      = 32
	symNonceLen     = 12
	symTagLen       = 16
	zLen            = 32
)

// Read is a helper function that calls Reader.Read using io.ReadFull.
// On return, n == len(b) if and only if err == nil.
func randRead(b []byte) {
	_, err := io.ReadFull(randReader, b)
	if err != nil {
		panic(err)
	}
}

// hash hashes a slice of byte arrays,
func hash(domain []byte, tuple ...[]byte) []byte {
	hash := sha512.New()
	/* #nosec */
	hash.Write(domain)
	for _, t := range tuple {
		/* #nosec */
		hash.Write(t)
	}
	return hash.Sum(nil)
}

// initKdf creates HKDF instance initialized with hash
func initKdf(domain []byte, tuple ...[]byte) io.Reader {
	key := hash(nil, tuple...)

	return hkdf.New(sha512.New, key, domain, kdfInfoZ)

}

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func HashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof := initKdf(domain, data...)
	rz := makeZ(xof)

	for z == nil {
		// If the scalar is out of range, extract another number.
		if rz.Cmp(Curve.Params().N) >= 0 {
			rz = makeZ(xof)
		} else {
			z = rz
		}
	}
	return
}

func makeZ(reader io.Reader) *big.Int {
	buf := make([]byte, zLen)
	n, err := reader.Read(buf)
	if err != nil || n != zLen {
		panic("random read failed")
	}
	return new(big.Int).SetBytes(buf)
}

// padZ makes all bytes equal size adding zeroes to the beginning if necessary
func PadZ(z []byte) []byte {
	if len(z) == zLen {
		return z
	}

	newZ := make([]byte, zLen)
	copy(newZ[zLen-len(z):], z)
	return newZ
}

// randomZ generates big random 256 bit integer which must be less than curve's N parameter
func RandomZ() (z *big.Int) {
	rz := makeZ(randReader)
	for z == nil {
		// If the scalar is out of range, sample another random number.
		if rz.Cmp(Curve.Params().N) >= 0 {
			rz = makeZ(randReader)
		} else {
			z = rz
		}
	}
	return
}

// hashToPoint maps arrays of bytes to a valid curve point
func HashToPoint(domain []byte, data ...[]byte) *phe.Point {
	hash := hash(domain, data...)
	x, y := swu.HashToPoint(hash[:swu.PointHashLen])
	return &phe.Point{x, y}
}

// Encrypt generates 32 byte salt, uses master key & salt to generate per-data key & nonce with the help of HKDF
// Salt is concatenated to the ciphertext
func Encrypt(data, key []byte) ([]byte, error) {

	if len(key) != symKeyLen {
		return nil, errors.New("key must be exactly 32 bytes")
	}

	salt := make([]byte, symSaltLen)
	randRead(salt)

	kdf := hkdf.New(sha512.New, key, salt, encrypt)

	keyNonce := make([]byte, symKeyLen+symNonceLen)
	_, err := kdf.Read(keyNonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:symKeyLen])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, symSaltLen+len(data)+aesGcm.Overhead())
	copy(ct, salt)

	aesGcm.Seal(ct[:symSaltLen], keyNonce[symKeyLen:], data, nil)
	return ct, nil
}

// Decrypt extracts 32 byte salt, derives key & nonce and decrypts ciphertext
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != symKeyLen {
		return nil, errors.New("key must be exactly 32 bytes")
	}

	if len(ciphertext) < (symSaltLen + symTagLen) {
		return nil, errors.New("invalid ciphertext length")
	}

	salt := ciphertext[:symSaltLen]
	kdf := hkdf.New(sha512.New, key, salt, encrypt)

	keyNonce := make([]byte, symKeyLen+symNonceLen)
	_, err := kdf.Read(keyNonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:symKeyLen])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, 0)
	return aesGcm.Open(dst, keyNonce[symKeyLen:], ciphertext[symSaltLen:], nil)

}
