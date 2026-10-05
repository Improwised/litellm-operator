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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	litellmv1alpha1 "github.com/PalenaAI/litellm-operator/api/v1alpha1"
)

func TestProxyConfigHashChangesWithGuardrails(t *testing.T) {
	instance := &litellmv1alpha1.LiteLLMInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "hash-instance", Namespace: "default"},
	}
	labels := map[string]string{"app": "x"}

	base, err := proxyConfigHash(instance, labels, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := proxyConfigHash(instance, labels, nil)
	if err != nil {
		t.Fatal(err)
	}
	if base != again {
		t.Fatalf("hash not deterministic: %s vs %s", base, again)
	}

	guardrails := []litellmv1alpha1.LiteLLMGuardrail{{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "default"},
		Spec: litellmv1alpha1.LiteLLMGuardrailSpec{
			InstanceRef:   litellmv1alpha1.InstanceRef{Name: "hash-instance"},
			GuardrailName: "g",
			Provider:      "litellm_content_filter",
			Mode:          "pre_call",
		},
	}}
	withGuardrail, err := proxyConfigHash(instance, labels, guardrails)
	if err != nil {
		t.Fatal(err)
	}
	if withGuardrail == base {
		t.Fatal("adding a guardrail must change the config hash")
	}
}
