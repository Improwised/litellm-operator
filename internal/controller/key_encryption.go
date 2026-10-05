/*
Copyright 2026 bitkaio LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	corev1 "k8s.io/api/core/v1"

	litellmv1alpha1 "github.com/PalenaAI/litellm-operator/api/v1alpha1"
)

const (
	// keySecretPlainDataKey holds the minted key in plain text (the default).
	keySecretPlainDataKey = "api_key"
	// keySecretAgeDataKey holds the minted key as ASCII-armored age ciphertext
	// when spec.keySecretEncryption is set.
	keySecretAgeDataKey = "api_key.age"
)

func keySecretEncrypted(vk *litellmv1alpha1.LiteLLMVirtualKey) bool {
	return vk.Spec.KeySecretEncryption != nil && len(vk.Spec.KeySecretEncryption.AgeRecipients) > 0
}

// keySecretDataKeyFor is the data key under which the key Secret holds the key.
func keySecretDataKeyFor(vk *litellmv1alpha1.LiteLLMVirtualKey) string {
	if keySecretEncrypted(vk) {
		return keySecretAgeDataKey
	}
	return keySecretPlainDataKey
}

// encodeKeySecretData returns the complete data map for the key Secret. When
// encryption is on, the plaintext key never reaches the API server.
func encodeKeySecretData(vk *litellmv1alpha1.LiteLLMVirtualKey, apiKey string) (map[string][]byte, error) {
	if !keySecretEncrypted(vk) {
		return map[string][]byte{keySecretPlainDataKey: []byte(apiKey)}, nil
	}
	ct, err := ageEncrypt(vk.Spec.KeySecretEncryption.AgeRecipients, []byte(apiKey))
	if err != nil {
		return nil, fmt.Errorf("encrypt key for %q: %w", vk.Spec.KeyAlias, err)
	}
	return map[string][]byte{keySecretAgeDataKey: ct}, nil
}

// encryptExistingKeySecret re-encrypts a Secret minted before encryption was
// turned on: the plaintext entry is replaced by ciphertext. It reports whether
// the Secret changed.
func encryptExistingKeySecret(vk *litellmv1alpha1.LiteLLMVirtualKey, secret *corev1.Secret) (bool, error) {
	if !keySecretEncrypted(vk) {
		return false, nil
	}
	plain, ok := secret.Data[keySecretPlainDataKey]
	if !ok || len(plain) == 0 {
		return false, nil
	}
	data, err := encodeKeySecretData(vk, string(plain))
	if err != nil {
		return false, err
	}
	secret.Data = data
	return true, nil
}

func ageEncrypt(recipients []string, plaintext []byte) ([]byte, error) {
	parsed := make([]age.Recipient, 0, len(recipients))
	for _, r := range recipients {
		rec, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, fmt.Errorf("parse age recipient %q: %w", r, err)
		}
		parsed = append(parsed, rec)
	}
	var buf bytes.Buffer
	armored := armor.NewWriter(&buf)
	w, err := age.Encrypt(armored, parsed...)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := armored.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
