package webpush

import (
	"net"
	"net/http"
	"strconv"
	"time"
)

// Option represents a functional option for configuration.
type Option func(*WebPush)

// defaultPusher is a HTTP client used as the default pusher.
var defaultPusher = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// WithPusher sets the pusher.
// Defaults to a sane HTTP client for most use cases.
func WithPusher(pusher Pusher) Option {
	return func(c *WebPush) {
		c.pusher = pusher
	}
}

// defaultExpiry is the default duration with which to expire the push.
const defaultExpiry = 12 * time.Hour

// maxExpirty is the maximum duration with which to expire the push.
const maxExpiry = 24 * time.Hour

// WithExpiry sets the duration with which to expire the push.
func WithExpiry(d time.Duration) Option {
	return func(c *WebPush) {
		if d > maxExpiry {
			d = maxExpiry
		}
		c.expiry = d
	}
}

// PushOption represents a functional option for push configuration.
type PushOption func(req *http.Request)

// defaultTTL is the default TTL header value.
const defaultTTL = 60

// WithTTL sets the TTL header.
// Defaults to 60 seconds.
func WithTTL(ttl int) PushOption {
	return func(req *http.Request) {
		req.Header.Set("TTL", strconv.Itoa(ttl))
	}
}

// WithTopic sets the Topic header.
func WithTopic(topic string) PushOption {
	return func(req *http.Request) {
		req.Header.Set("Topic", topic)
	}
}

// WithUrgency sets the Urgency header.
func WithUrgency(urgency Urgency) PushOption {
	return func(req *http.Request) {
		if isValidUrgency(urgency) {
			req.Header.Set("Urgency", string(urgency))
		}
	}
}
