package internal

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		jwt := JWT{}
		err := jwt.Decode(jwtToken)
		assert.NoError(t, err)
		assert.NotNil(t, jwt.Header)
		assert.Contains(t, jwt.Header, "alg")
		assert.Contains(t, jwt.Header, "typ")
		assert.NotNil(t, jwt.Payload)
		assert.Contains(t, jwt.Payload, "iat")
		assert.Contains(t, jwt.Payload, "name")
		assert.Contains(t, jwt.Payload, "sub")
		assert.NotNil(t, jwt.Signature)
		assert.Equal(t, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", jwt.Signature)
	})

	t.Run("not a valid JWT", func(t *testing.T) {
		jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
		jwt := JWT{}
		err := jwt.Decode(jwtToken)
		assert.Error(t, err)
		assert.EqualError(t, err, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ is not a JWT")
		assert.Nil(t, jwt.Header)
		assert.Nil(t, jwt.Payload)
		assert.Equal(t, "", jwt.Signature)
	})

	t.Run("invalid JWT Header", func(t *testing.T) {
		jwtToken := "acbded.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
		jwt := JWT{}
		err := jwt.Decode(jwtToken)
		assert.Error(t, err)
		assert.EqualError(t, err, "invalid character 'i' looking for beginning of value")
		assert.Nil(t, jwt.Header)
		assert.Nil(t, jwt.Payload)
		assert.Equal(t, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", jwt.Signature)
	})
}

func TestDecodePart(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		testString := `{"unit":"test"}`
		base64Str := base64.URLEncoding.EncodeToString([]byte(testString))
		jwt := JWT{}
		err := jwt.decodePart(base64Str, &jwt.Header)
		assert.NoError(t, err)
		assert.NotNil(t, jwt.Header)
		assert.Nil(t, jwt.Payload)
		assert.Equal(t, "test", jwt.Header["unit"])
	})

	t.Run("not base64 encoded", func(t *testing.T) {
		testString := "No base64"
		jwt := JWT{}
		err := jwt.decodePart(testString, &jwt.Header)
		assert.Error(t, err)
		assert.EqualError(t, err, "illegal base64 data at input byte 2")
		assert.Nil(t, jwt.Header)
		assert.Nil(t, jwt.Payload)
	})

	t.Run("no JSON data", func(t *testing.T) {
		testString := "somestring"
		base64Str := base64.URLEncoding.EncodeToString([]byte(testString))
		jwt := JWT{}
		err := jwt.decodePart(base64Str, &jwt.Header)
		assert.Error(t, err)
		assert.EqualError(t, err, "invalid character 's' looking for beginning of value")
		assert.Nil(t, jwt.Header)
		assert.Nil(t, jwt.Payload)
	})

	t.Run("should not contain .", func(t *testing.T) {
		testString := "somestring."
		base64Str := base64.URLEncoding.EncodeToString([]byte(testString))
		jwt := JWT{}
		err := jwt.decodePart(base64Str+".", &jwt.Header)
		assert.Error(t, err)
		assert.EqualError(t, err, "c29tZXN0cmluZy4=. doesn't look like a JWT part")
		assert.Nil(t, jwt.Header)
		assert.Nil(t, jwt.Payload)
	})
}
