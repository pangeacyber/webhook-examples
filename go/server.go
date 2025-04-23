package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var SIGNING_SECRET = os.Getenv("SIGNING_SECRET")

func verifySignature(secretKey []byte, signature string, payload []byte) bool {
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(decodedSignature, expectedMAC)
}

func decryptPayload(secret []byte, cipherBody []byte) ([]byte, error) {
	aes, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	nonce := cipherBody[:gcm.NonceSize()]
	cipherBody = cipherBody[gcm.NonceSize():]

	plainBytes, err := gcm.Open(nil, nonce, cipherBody, nil)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func webhook(w http.ResponseWriter, r *http.Request) {
	signature := r.Header.Get("x-signature-sha256")
	if signature == "" {
		http.Error(w, "Missing signature", http.StatusBadRequest)
		return
	}

	encryptedBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(SIGNING_SECRET)
	if err != nil {
		http.Error(w, "Invalid signing secret", http.StatusServiceUnavailable)
		return
	}

	if !verifySignature(decodedSecret, signature, encryptedBody) {
		fmt.Println("Invalid signature")
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	body, err := decryptPayload(decodedSecret, encryptedBody)
	if err != nil {
		fmt.Println("Error decrypting payload", err)
		http.Error(w, "Failed to decrypt content", http.StatusServiceUnavailable)
		return
	}

	// Now that the signature has been verified and the payload decrypted,
	// additional logic on `body` may happen here.
	fmt.Println("Decrypted payload", string(body))

	fmt.Fprint(w, "OK")
}

func main() {
	http.HandleFunc("/webhook", webhook)
	fmt.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
