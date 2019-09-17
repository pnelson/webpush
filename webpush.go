// Package webpush implements Web Push helpers.
package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/pnelson/jwt"
)

var (
	// hash is the SHA-256 hash algorithm used by ECDSA for web push.
	hash = sha256.New

	// curve is the P-256 curve used by ECDSA for web push.
	curve = elliptic.P256()
)

// Pusher represents the ability to perform web push requests.
type Pusher interface {
	Do(req *http.Request) (*http.Response, error)
}

// WebPush represents the Web Push application server.
type WebPush struct {
	pusher     Pusher
	publicKey  []byte // point on curve
	privateKey []byte // PEM
	subscriber string
	expiry     time.Duration
}

// Subscription represents a subscription to a Web Push service.
type Subscription struct {
	Endpoint   string
	PublicKey  []byte // p256dh
	PrivateKey []byte // auth
}

// New returns a new Web Push application server.
// privateKey must be a PEM-encoded ECDSA private key.
// Generate a valid key with GenerateKey.
func New(privateKey []byte, subscriber string, opts ...Option) (*WebPush, error) {
	key, err := decodePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	c := &WebPush{
		pusher:     defaultPusher,
		publicKey:  elliptic.Marshal(curve, key.PublicKey.X, key.PublicKey.Y),
		privateKey: privateKey,
		subscriber: subscriber,
		expiry:     defaultExpiry,
	}
	for _, option := range opts {
		option(c)
	}
	return c, nil
}

// PublicKey returns the public application server key for
// use in JavaScript client web push subscription.
func (c *WebPush) PublicKey() string {
	return encode(c.publicKey)
}

// Push sends a push notification.
func (c *WebPush) Push(s *Subscription, b []byte, opts ...PushOption) (*http.Response, error) {
	r, err := newRequest(s)
	if err != nil {
		return nil, err
	}
	data, err := r.encrypt(b)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(data)
	req, err := http.NewRequest(http.MethodPost, s.Endpoint, body)
	if err != nil {
		return nil, err
	}
	token, err := c.sign(s)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "WebPush "+token)
	req.Header.Set("Encryption", "salt="+encode(r.salt))
	req.Header.Set("Crypto-Key", fmt.Sprintf("dh=%s; p256ecdsa=%s", encode(r.localPublicKey), encode(c.publicKey)))
	req.Header.Set("TTL", strconv.Itoa(defaultTTL))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aesgcm")
	for _, option := range opts {
		option(req)
	}
	return c.pusher.Do(req)
}

func (c *WebPush) sign(s *Subscription) (string, error) {
	u, err := url.Parse(s.Endpoint)
	if err != nil {
		return "", err
	}
	t := jwt.New(jwt.ES256)
	t.Claims["aud"] = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	t.Claims["exp"] = time.Now().Add(c.expiry).Unix()
	t.Claims["sub"] = c.subscriber
	return t.Sign(c.privateKey)
}

type request struct {
	prk                   []byte
	salt                  []byte
	localPublicKey        []byte
	localPrivateKey       []byte
	subscriptionPublicKey []byte
}

func newRequest(s *Subscription) (*request, error) {
	auth := []byte("Content-Encoding: auth\x00")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	localPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	localPublicKey := elliptic.Marshal(curve, x, y)
	x, y = elliptic.Unmarshal(curve, s.PublicKey)
	if x == nil {
		return nil, errors.New("webpush: subscription public key is not on the curve")
	}
	sx, _ := curve.ScalarMult(x, y, localPrivateKey)
	prk, err := hkd(sx.Bytes(), s.PrivateKey, auth, curve.Params().BitSize/8)
	if err != nil {
		return nil, err
	}
	r := &request{
		prk:                   prk,
		salt:                  salt,
		localPublicKey:        localPublicKey,
		localPrivateKey:       localPrivateKey,
		subscriptionPublicKey: s.PublicKey,
	}
	return r, nil
}

func (r *request) encrypt(b []byte) ([]byte, error) {
	const cekSize = 16 // 128 bits
	cek, err := r.context("aesgcm", cekSize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, err := r.context("nonce", nonceSize)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(make([]byte, 0), nonce, append(make([]byte, 2), b...), nil), nil
}

func (r *request) context(kind string, size int) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("Content-Encoding: ")
	buf.WriteString(kind)
	buf.WriteByte(0)
	buf.WriteString("P-256")
	buf.WriteByte(0)
	subscriptionPublicKeyLength := make([]byte, 2)
	binary.BigEndian.PutUint16(subscriptionPublicKeyLength, uint16(len(r.subscriptionPublicKey)))
	buf.Write(subscriptionPublicKeyLength)
	buf.Write(r.subscriptionPublicKey)
	localPublicKeyLength := make([]byte, 2)
	binary.BigEndian.PutUint16(localPublicKeyLength, uint16(len(r.localPublicKey)))
	buf.Write(localPublicKeyLength)
	buf.Write(r.localPublicKey)
	return hkd(r.prk, r.salt, buf.Bytes(), size)
}

func hkd(secret, salt, info []byte, size int) ([]byte, error) {
	hr := hkdf.New(hash, secret, salt, info)
	key := make([]byte, size)
	_, err := io.ReadFull(hr, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Urgency indicates to the push service how important a message is to the user.
// This can be used by the push service to help conserve the battery life of a
// user’s device by only waking up for important messages when battery is low.
type Urgency string

const (
	// UrgencyVeryLow requires the device to be on power and wifi.
	// Useful for advertisements.
	UrgencyVeryLow Urgency = "very-low"

	// UrgencyLow requires the device to be on either power or wifi.
	// Useful for topic updates.
	UrgencyLow Urgency = "low"

	// UrgencyNormal requires the device to be on neither power nor wifi.
	// Useful for chats or calendar reminders.
	UrgencyNormal Urgency = "normal"

	// UrgencyHigh will operate on low battery.
	// Useful for time-sensitive alerts.
	UrgencyHigh Urgency = "high"
)

// String implements the fmt.Stringer interface.
func (u Urgency) String() string {
	if !isValidUrgency(u) {
		return ""
	}
	return string(u)
}

func isValidUrgency(u Urgency) bool {
	switch u {
	case UrgencyVeryLow, UrgencyLow, UrgencyNormal, UrgencyHigh:
		return true
	}
	return false
}

// DecodeKey returns the bytes represented by the base64 string s.
// This can be used to decode new subscription p256dh and auth keys.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// decodePrivateKey decodes a PEM-encoded ECDSA private key.
func decodePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("webpush: invalid ecdsa private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// encodePrivateKey encodes an ECDSA private key to PEM format.
func encodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block), nil
}

// encode returns b encoded as a padding-free base64 string.
func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateKey returns a new ECDSA private key from a secure random source.
func GenerateKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return encodePrivateKey(key)
}
