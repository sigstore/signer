//
// Copyright 2022 The Sigstore Authors.
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

package pem

import (
	"bytes"
	"encoding/pem"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"testing"
)

func FuzzLoadCertificates(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b, _ := pem.Decode(data)
		if b == nil {
			t.Skip("invalid pem")
		}

		result, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
		if err != nil {
			if result != nil {
				t.Errorf("result %v should be nil when there is an error %v", result, err)
			}
			t.Skip("invalid pem")
		}
		for _, cert := range result {
			if len(cert.Raw) == 0 {
				t.Errorf("x509 cert raw is empty")
			}
		}
	})
}

func FuzzUnmarshalCertificatesFromPEM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b, _ := pem.Decode(data)
		if b == nil {
			t.Skip("invalid pem")
		}
		result, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
		if err != nil {
			if result != nil {
				t.Errorf("result %v should be nil when there is an error %v", result, err)
			}
			t.Skip("invalid pem")
		}
		for _, cert := range result {
			if len(cert.Raw) == 0 {
				t.Errorf("x509 cert raw is empty")
			}
		}
	})
}

func FuzzUnmarshalPEMToPublicKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b, _ := pem.Decode(data)
		if b == nil {
			t.Skip("invalid pem")
		}
		result, err := cryptoutils.UnmarshalPEMToPublicKey(data)
		if err != nil {
			if result != nil {
				t.Errorf("result %v should be nil when there is an error %v", result, err)
			}
			t.Skip("invalid pem")
		}
		if result == nil {
			t.Errorf("result %v should not be nil", result)
		}
	})
}
