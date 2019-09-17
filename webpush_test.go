package webpush

import (
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"testing"
)

type testPusher struct {
	code int
}

func (p testPusher) Do(req *http.Request) (*http.Response, error) {
	const retryAfter = "419"
	resp := &http.Response{
		StatusCode: p.code,
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(nil),
		Request:    req,
	}
	if p.code == http.StatusTooManyRequests {
		resp.Header.Set("Retry-After", retryAfter)
	}
	return resp, nil
}

const (
	p256dh = "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM="
	auth   = "tBHItJI5svbpez7KI4CCXg=="
)

var withDefaultTestPusher = WithPusher(&testPusher{code: http.StatusCreated})

func testWebPush(t *testing.T, opts ...Option) (*WebPush, *Subscription) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts = append([]Option{withDefaultTestPusher}, opts...)
	c, err := New(key, "test", opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	publicKey, err := DecodeKey(p256dh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	privateKey, err := DecodeKey(auth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := &Subscription{
		Endpoint:   "https://example.com",
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
	return c, s
}

func TestWebPush(t *testing.T) {
	c, s := testWebPush(t)
	resp, err := c.Push(s, []byte("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	for _, key := range []string{"Authorization", "Encryption", "Crypto-Key", "TTL", "Content-Type", "Content-Encoding"} {
		v := resp.Request.Header.Get(key)
		if v == "" {
			t.Errorf("should have %s header", key)
		}
	}
	for _, key := range []string{"Topic", "Urgency"} {
		v := resp.Request.Header.Get(key)
		if v != "" {
			t.Errorf("should not have %s header", key)
		}
	}
}

func TestWithTTL(t *testing.T) {
	const ttl = 419
	c, s := testWebPush(t)
	resp, err := c.Push(s, []byte("test"), WithTTL(ttl))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	have := resp.Request.Header.Get("TTL")
	want := strconv.Itoa(ttl)
	if have != want {
		t.Errorf("TTL header\nhave %q\nwant %q", have, want)
	}
}

func TestWithTopic(t *testing.T) {
	const want = "test"
	c, s := testWebPush(t)
	resp, err := c.Push(s, []byte("test"), WithTopic(want))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	have := resp.Request.Header.Get("Topic")
	if have != want {
		t.Errorf("Topic header\nhave %q\nwant %q", have, want)
	}
}

func TestWithUrgency(t *testing.T) {
	const want = "high"
	c, s := testWebPush(t)
	resp, err := c.Push(s, []byte("test"), WithUrgency(Urgency(want)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	have := resp.Request.Header.Get("Urgency")
	if have != want {
		t.Errorf("Urgency header\nhave %q\nwant %q", have, want)
	}
}

func TestDecodeKey(t *testing.T) {
	auth := "tBHItJI5svbpez7KI4CCXg=="
	want := []byte{0xb4, 0x11, 0xc8, 0xb4, 0x92, 0x39, 0xb2, 0xf6, 0xe9, 0x7b, 0x3e, 0xca, 0x23, 0x80, 0x82, 0x5e}
	have, err := DecodeKey(auth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("DecodeKey\nhave %x\nwant %v", have, want)
	}
}

func TestDecodeKeyBugs(t *testing.T) {
	tests := []string{
		"rPDS4bHk-eoYFllt5OWAsA",
		"BJfFZCmKtvdghPyDhOdk4xDAwC-qnt6KZj5Y9YCY-GiTbtFn1gnS-mJRcABGA5z5rD7bUzIAdx2obbzersF-kSg",
	}
	for i, tt := range tests {
		_, err := DecodeKey(tt)
		if err != nil {
			t.Fatalf("%d. DecodeKey unexpected error: %v", i+1, err)
		}
	}
}
