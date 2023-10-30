# Verifier
Verifier provides the functionality for signing and verifying messages to prevent tampering.
This package was created, inspired by Ruby's ``ActiveSupport:MessageVerifier``.

## Installation
```
go get github.com/kondo97/verifier
```

## Example
```golang
v := NewVerifier("secret") // It is possible to sign regardless of the type.
g, err := v.Generate("message")
```

### purpose
```golang
v := NewVerifier("secret") 
g, err := v.Generate("message")
msg, err := v.Verify(g, "purpose") // msg = "secret"
msg, err := v.Verify(g, "diffrent purpose") // msg = "", err = "diffrent purpose"
```

### expiresAt
```golang
v := NewVerifier("secret", time.Now().Add(24 * time.Hour)) 
g, err := v.Generate("message")
msg, err := v.Verify(g) // msg = "secret"

v := NewVerifier("secret", time.Now().Add(-24 * time.Hour)) 
g, err := v.Generate("message")
msg, err := v.Verify(g) // msg = "", err = "expired"
```

### Rotate
```golang
v := NewVerifier("secret") 
g, err := v.Generate("message")

v2 := NewVerifier("new secret")
msg, err := v2.Verify(g) //  msg = "", err = "invalid signature"

v2.Rorate("secret")
msg, err := v2.Verify(g) // msg = "secret"
```