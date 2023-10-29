# Verifier
Verifier provides the functionality for signing and verifying messages to prevent tampering.
This package was created, inspired by Ruby's ``ActiveSupport:MessageVerifier``.

## Installation
```
go get github.com/kondo97/verifier
```

## Example
```golang
v := NewVerifier("secret") // It is possible to sign regardless of the type."

g, err := v.Generate("message", time.Now().Add(24 * time.Hour), "purpose")
// g = "eyJNZXNzYWdlIjoiaGVsbG8iLCJFeHBpcmVzQXQiOiIyMDIzLTEwLTMwVDE5OjE1OjA4KzA5OjAwIiwiUHVycG9zZSI6ImV4YW1wbGUifQ==--e58bf06313bf71ec6ab326323124b5c74d1d943056b770681fe425ee8e3bd2d0"

msg, err := v.Verify(g, "purpose") // msg = "secret"

// if expiresAt is expired,
// msg = "", err = "expired"

msg, err := v.Verify(g, "diffrentPurpose") // msg = "", err = "diffrent purpose"
```