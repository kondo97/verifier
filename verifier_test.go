package verifier

import (
	"testing"
	"time"
)

func TestNewVerifier(t *testing.T) {
	const secret = "secret"
	t.Run("success", func(t *testing.T) {
		v := NewVerifier(secret)
		if v.secret != secret {
			t.Errorf("expected secret to be secret, got %s", v.secret)
		}
	})
}

func TestGenerate(t *testing.T) {
	const secret = "secret"
	v := NewVerifier(secret)
	t.Run("success when message is string", func(t *testing.T) {
		const message = "hello"
		signedMessage, err := v.Generate(message, time.Time{}, "")
		if err != nil {
			t.Errorf("expected err to be nil, got %s", err)
		}
		if signedMessage == "" {
			t.Errorf("expected signedMessage to be not empty")
		}
	})

	t.Run("success when message is struct", func(t *testing.T) {
		message := struct { Message string } { Message: "hello" }
		signedMessage, err := v.Generate(message, time.Time{}, "")
		if err != nil {
			t.Errorf("expected err to be nil, got %s", err)
		}
		if signedMessage == "" {
			t.Errorf("expected signedMessage to be not empty")
		}
	})
}

func TestVerify(t *testing.T) {
  const secret = "secret"
	const message = "hello"
	v := NewVerifier(secret)
	signedMessage, _ := v.Generate(message, time.Time{}, "")

  t.Run("success, secret is correct", func(t *testing.T) {
		v := NewVerifier(secret)
    verifiedMessage, err := v.Verify(signedMessage, "")
		if err != nil {
			t.Errorf("expected err to be nil, got %s", err)
		}
		if verifiedMessage != message {
			t.Errorf("expected verifiedMessage to be %s, got %s", message, verifiedMessage)
		}
	})

	t.Run("success, secret is correct, message is struct", func(t *testing.T) {
		v := NewVerifier(secret)
		type TestMessage struct {
			Greeting string
		}
		message := TestMessage{ Greeting: "hello" }
	  signedMessage, _ := v.Generate(message, time.Time{}, "")
    verifiedMessage, err := v.Verify(signedMessage, "")
		if err != nil {
			t.Errorf("expected err to be nil, got %s", err)
		}
    
		s := verifiedMessage.(map[string]interface{})
		if s["Greeting"] != message.Greeting {
			t.Errorf("expected verifiedMessage to be %s, got %s", message, verifiedMessage)
		}
	})

	t.Run("failure, secret is not correct", func(t *testing.T) {
		wrongSecret := "wrongSecret"
		v := NewVerifier(wrongSecret)
    verifiedMessage, err := v.Verify(signedMessage, "")
		if verifiedMessage != "" {
			t.Errorf("expected verifiedMessage to be empty, got %s", verifiedMessage)
		}
		if err == nil {
			t.Errorf("expected err to be not nil")
		}
	})

	t.Run("failure, message is not correct purpose", func(t *testing.T) {
    g, _ := v.Generate(message, time.Time{}, "purpose")
		verifiedMessage, err := v.Verify(g, "differentPurpose")
		if verifiedMessage != "" {
			t.Errorf("expected verifiedMessage to be empty, got %s", verifiedMessage)
		}
		if err == nil {
			t.Errorf("expected err to be not nil")
		}
	})

	t.Run("failure, message is expired", func(t *testing.T) {
		expiredAt := time.Now().Add(-24 * time.Hour)
		g, _ := v.Generate(message, expiredAt, "")
		verifiedMessage, err := v.Verify(g, "")
		if verifiedMessage != "" {
			t.Errorf("expected verifiedMessage to be empty, got %s", verifiedMessage)
		}
		if err == nil {
			t.Errorf("expected err to be not nil")
		}
	})

	t.Run("success, secret is rotated", func(t *testing.T) {
		wrongSecret := "wrongSecret"
		v := NewVerifier(wrongSecret)
		v.Rotate(secret)
		verifiedMessage, err := v.Verify(signedMessage, "")
		if err != nil {
			t.Errorf("expected err to be nil, got %s", err)
		}

		if verifiedMessage != message {
			t.Errorf("expected verifiedMessage to be %s, got %s", message, verifiedMessage)
		}
	})
}

func TestRotate(t *testing.T) {
	const secret = "secret"
	t.Run("success", func(t *testing.T) {
		v := NewVerifier(secret)
		r := "newSecret"
		v.Rotate(secret)
		if v.rotations[0] == r {
			t.Errorf("expected rotations to be 1, got %d", len(v.rotations))
		}
	})
}