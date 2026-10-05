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
	"context"
	"io"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	litellmv1alpha1 "github.com/PalenaAI/litellm-operator/api/v1alpha1"
	"github.com/PalenaAI/litellm-operator/internal/litellm"
)

func ageDecrypt(identity *age.X25519Identity, ciphertext []byte) (string, error) {
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(ciphertext)), identity)
	if err != nil {
		return "", err
	}
	out, err := io.ReadAll(r)
	return string(out), err
}

func TestKeySyncHashIgnoresEncryption(t *testing.T) {
	base := litellmv1alpha1.LiteLLMVirtualKeySpec{InstanceRef: litellmv1alpha1.InstanceRef{Name: "inst"}, KeyAlias: "a"}
	enc := base
	enc.KeySecretEncryption = &litellmv1alpha1.KeySecretEncryptionSpec{AgeRecipients: []string{"age1x"}}
	if keySyncHash(enc) != keySyncHash(base) {
		t.Error("keySecretEncryption must not change the sync hash (it never reaches LiteLLM)")
	}
}

func TestAgeEncryptRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := ageEncrypt([]string{id.Recipient().String()}, []byte("sk-roundtrip"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("sk-roundtrip")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := ageDecrypt(id, ct)
	if err != nil || got != "sk-roundtrip" {
		t.Fatalf("round trip failed: %q, %v", got, err)
	}
	if _, err := ageEncrypt([]string{"not-a-recipient"}, []byte("x")); err == nil {
		t.Fatal("expected an error for an invalid recipient")
	}
}

var _ = Describe("LiteLLMVirtualKey key Secret encryption", func() {
	ctx := context.Background()
	const (
		ns           = "default"
		instanceName = "vkenc-instance"
		keyName      = "vkenc-key"
		secretName   = keyName + "-key"
		mintedKey    = "sk-minted-secret-value"
	)

	var identity *age.X25519Identity

	newReconciler := func() *LiteLLMVirtualKeyReconciler {
		mock := litellm.NewMockClient()
		mock.MockKeys.GenerateFunc = func(context.Context, litellm.KeyGenerateRequest) (*litellm.KeyGenerateResponse, error) {
			return &litellm.KeyGenerateResponse{Key: mintedKey, Token: "hashed-token"}, nil
		}
		return &LiteLLMVirtualKeyReconciler{
			Client:               k8sClient,
			Scheme:               k8sClient.Scheme(),
			LiteLLMClientFactory: func(string, string, ...litellm.ClientOption) litellm.Client { return mock },
		}
	}

	reconcileKey := func(r *LiteLLMVirtualKeyReconciler) {
		GinkgoHelper()
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: keyName, Namespace: ns}})
		Expect(err).NotTo(HaveOccurred())
	}

	getSecret := func() *corev1.Secret {
		GinkgoHelper()
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: ns}, &secret)).To(Succeed())
		return &secret
	}

	getKey := func() *litellmv1alpha1.LiteLLMVirtualKey {
		GinkgoHelper()
		var vk litellmv1alpha1.LiteLLMVirtualKey
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: keyName, Namespace: ns}, &vk)).To(Succeed())
		return &vk
	}

	createKey := func(enc *litellmv1alpha1.KeySecretEncryptionSpec) {
		GinkgoHelper()
		Expect(k8sClient.Create(ctx, &litellmv1alpha1.LiteLLMVirtualKey{
			ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: ns},
			Spec: litellmv1alpha1.LiteLLMVirtualKeySpec{
				InstanceRef:         litellmv1alpha1.InstanceRef{Name: instanceName},
				KeyAlias:            keyName,
				KeySecretEncryption: enc,
			},
		})).To(Succeed())
	}

	BeforeEach(func() {
		var err error
		identity, err = age.GenerateX25519Identity()
		Expect(err).NotTo(HaveOccurred())

		instance := &litellmv1alpha1.LiteLLMInstance{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: instanceName, Namespace: ns}, instance); err != nil && errors.IsNotFound(err) {
			instance = &litellmv1alpha1.LiteLLMInstance{
				ObjectMeta: metav1.ObjectMeta{Name: instanceName, Namespace: ns},
				Spec: litellmv1alpha1.LiteLLMInstanceSpec{
					MasterKey: litellmv1alpha1.MasterKeySpec{AutoGenerate: true},
					Database: litellmv1alpha1.DatabaseSpec{
						External: &litellmv1alpha1.ExternalDBSpec{
							ConnectionSecretRef: litellmv1alpha1.SecretKeyRef{Name: "db", Key: "url"},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		}
		instance.Status.Ready = true
		Expect(k8sClient.Status().Update(ctx, instance)).To(Succeed())

		mk := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: instanceName + "-master-key", Namespace: ns}, mk); err != nil && errors.IsNotFound(err) {
			Expect(k8sClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: instanceName + "-master-key", Namespace: ns},
				Data:       map[string][]byte{"master-key": []byte("sk-master")},
			})).To(Succeed())
		}
	})

	AfterEach(func() {
		vk := &litellmv1alpha1.LiteLLMVirtualKey{ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: ns}}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(vk), vk); err == nil {
			if len(vk.GetFinalizers()) > 0 {
				vk.SetFinalizers(nil)
				_ = k8sClient.Update(ctx, vk)
			}
			_ = k8sClient.Delete(ctx, vk)
		}
		_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns}})
		_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: instanceName + "-master-key", Namespace: ns}})
		_ = k8sClient.Delete(ctx, &litellmv1alpha1.LiteLLMInstance{ObjectMeta: metav1.ObjectMeta{Name: instanceName, Namespace: ns}})
	})

	It("stores only age ciphertext when keySecretEncryption is set", func() {
		createKey(&litellmv1alpha1.KeySecretEncryptionSpec{AgeRecipients: []string{identity.Recipient().String()}})
		reconcileKey(newReconciler())

		secret := getSecret()
		Expect(secret.Data).NotTo(HaveKey("api_key"))
		Expect(secret.Data).To(HaveKey("api_key.age"))
		for _, v := range secret.Data {
			Expect(string(v)).NotTo(ContainSubstring(mintedKey))
		}
		plain, err := ageDecrypt(identity, secret.Data["api_key.age"])
		Expect(err).NotTo(HaveOccurred())
		Expect(plain).To(Equal(mintedKey))

		Expect(getKey().Status.KeySecretRef.Key).To(Equal("api_key.age"))
	})

	It("re-encrypts an existing plaintext Secret when encryption is turned on", func() {
		createKey(nil)
		r := newReconciler()
		reconcileKey(r)
		Expect(getSecret().Data).To(HaveKeyWithValue("api_key", []byte(mintedKey)))

		vk := getKey()
		vk.Spec.KeySecretEncryption = &litellmv1alpha1.KeySecretEncryptionSpec{AgeRecipients: []string{identity.Recipient().String()}}
		Expect(k8sClient.Update(ctx, vk)).To(Succeed())
		reconcileKey(r)

		secret := getSecret()
		Expect(secret.Data).NotTo(HaveKey("api_key"))
		plain, err := ageDecrypt(identity, secret.Data["api_key.age"])
		Expect(err).NotTo(HaveOccurred())
		Expect(plain).To(Equal(mintedKey), "the same key, not a new one, must be kept")
		Expect(getKey().Status.KeySecretRef.Key).To(Equal("api_key.age"))
	})

	It("rejects a malformed age recipient at admission", func() {
		err := k8sClient.Create(ctx, &litellmv1alpha1.LiteLLMVirtualKey{
			ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: ns},
			Spec: litellmv1alpha1.LiteLLMVirtualKeySpec{
				InstanceRef:         litellmv1alpha1.InstanceRef{Name: instanceName},
				KeyAlias:            keyName,
				KeySecretEncryption: &litellmv1alpha1.KeySecretEncryptionSpec{AgeRecipients: []string{"ssh-ed25519 AAAA"}},
			},
		})
		Expect(err).To(HaveOccurred())
	})
})
