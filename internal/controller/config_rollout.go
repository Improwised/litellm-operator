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
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"

	litellmv1alpha1 "github.com/PalenaAI/litellm-operator/api/v1alpha1"
	"github.com/PalenaAI/litellm-operator/internal/resources"
)

// proxyConfigHash digests the ConfigMap data the instance controller renders
// for this instance (the same content the pods mount), so any change to it
// produces a different pod template and therefore a rollout.
func proxyConfigHash(
	instance *litellmv1alpha1.LiteLLMInstance,
	labels map[string]string,
	guardrails []litellmv1alpha1.LiteLLMGuardrail,
) (string, error) {
	cm, err := resources.BuildConfigMap(instance, labels, guardrails)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, k := range slices.Sorted(maps.Keys(cm.Data)) {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(cm.Data[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
