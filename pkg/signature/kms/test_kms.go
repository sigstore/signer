//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kms implements the interface to access various ksm services
package kms

import (
	"context"
	"crypto"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestGet ensures that kms.Get() can return multiple instances of clients.
// The various kms modules to be tested must also be imported above.

type TestSignerVerifierA struct {
	SignerVerifier
}

type TestSignerVerifierB struct {
	SignerVerifier
}

type TestSignerVerifierPluginClient struct {
	SignerVerifier
}

func TestGet(t *testing.T) {
	t.Parallel()

	testHashFunc := crypto.SHA3_384
	testContext := context.Background()

	tests := []struct {
		name          string
		keyResourceID string
		kind          reflect.Type
	}{
		{
			name:          "fakekms",
			keyResourceID: "fakekms://my-key",
			kind:          reflect.TypeOf(TestSignerVerifierA{}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signerVerifier, err := Get(testContext, tc.keyResourceID, testHashFunc)
			if diff := cmp.Diff(nil, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tc.kind, reflect.TypeOf(signerVerifier)); diff != "" {
				t.Errorf("unexpected signerVerifier type (-want +got): \n%s", diff)
			}
		})
	}
}
