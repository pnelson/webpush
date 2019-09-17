# webpush

Package webpush implements the Web Push protocol.

## Usage

```go
c, err := webpush.New(priv, "mailto:foo@example.com")
if err != nil {
  log.Fatal(err)
}
s := &webpush.Subscription{
  Endpoint:   "https://example.com",
  PublicKey:  webpush.DecodeKey(p256dh),
  PrivateKey: webpush.DecodeKey(auth),
}
resp, err := c.Push(s, []byte("hello, world"), webpush.WithTTL(0))
if err != nil {
  log.Fatal(err)
}
defer resp.Body.Close()
```
