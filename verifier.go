package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const separator = "--"
const separatorLength = len(separator)

type Verifier struct {
	secret string
	rotations []string
}

type Message struct {
	Message any
	ExpiresAt string
	Purpose string
}

func NewVerifier(secret string) Verifier {
	return Verifier{secret: secret}
}

func (v Verifier) Generate(value any, expiresAt time.Time, purpose string) (string, error) {
	message := Message{Message: value}
	if purpose != "" {
		message.Purpose = purpose
	}
	if !expiresAt.IsZero(){
		message.ExpiresAt = expiresAt.Format(time.RFC3339)
	}
	marshalData, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	data := encode(marshalData)
	digest := generateDigest(data, v.secret)
	return data + separator + digest, nil
}

func (v Verifier) Verify(signedMessage string, purpose string) (any, error) {
	message, err := verify(signedMessage, v)
	if err != nil {
		return "", err
	}
	marshalData, err := decode(message)
	if err != nil {
    return "", err
  }
	var value Message
  if err := json.Unmarshal(marshalData, &value); err != nil {
	  return "", err
  }
	if value.Purpose != "" && value.Purpose != purpose {
		return "", errors.New("different purpose")
	}
	if value.ExpiresAt != "" {
		parsedTime, _ := time.Parse(time.RFC3339, value.ExpiresAt)
		if parsedTime.Before(time.Now()) {
			return "", errors.New("expired")
		}
	}
	return value.Message, nil
}

func (v *Verifier) Rotate(secret string) {
  v.rotations = append(v.rotations, secret)
}

func encode (data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decode (data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func generateDigest(data, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func verify(signedMessage string,  v Verifier) (string, error) {
	data, digest := getDataAndDigestFrom(signedMessage)
	if digestMatchedData(data, digest, v.secret) {
		return data, nil
	}
	for _, r := range v.rotations {
		if digestMatchedData(data, digest, r) {
			return data, nil
		}
	}
	return "", errors.New("invalid signature")
}

func getDataAndDigestFrom(signedMessage string) (string, string) {
	index := separateIndexFor(signedMessage)
	data := signedMessage[:index]
	digest := signedMessage[index + separatorLength:]
	return data, digest
}

func separateIndexFor(signedMessage string) int {
	index := len(signedMessage) - digesLengthInHex() - separatorLength
	return index
}

func digesLengthInHex() int {
	return sha256.BlockSize
}

func digestMatchedData(data, digest, secret string) bool {
	return subtle.ConstantTimeCompare([]byte(digest), []byte(generateDigest(data, secret))) == 1
}