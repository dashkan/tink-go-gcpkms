// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcpkms_test

import (
	"bytes"
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
)

const (
	// macKeyName is an HMAC-SHA256 CryptoKeyVersion in the KMS key ring hosted in the Google Cloud
	// project `tink-test-infrastructure`, used for Tink integration tests. MAC operations are bound
	// to a specific CryptoKeyVersion, so the name includes the version.
	macKeyName = "projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/mac-key/cryptoKeyVersions/1"

	// maxMACDataSize is the maximum size of the data that GRPCMAC sends to GCP KMS. Kept in sync
	// with kmsMaxMACDataSize in gcp_kms_grpc_mac.go, which is unexported.
	maxMACDataSize = 64 * 1024
)

var (
	macData      = []byte("This is some data to authenticate.")
	macOtherData = []byte("This is some other data.")
)

// newKMSClient returns a GCP KMS client that authenticates with the test service account
// credentials. The client is closed when the test finishes.
func newKMSClient(ctx context.Context, t *testing.T) *kms.KeyManagementClient {
	t.Helper()
	credentialsOpt := option.WithAuthCredentialsFile(option.ServiceAccount, testFilePath(t, credFile))
	client, err := kms.NewKeyManagementClient(ctx, credentialsOpt)
	if err != nil {
		t.Fatalf("kms.NewKeyManagementClient() err = %v, want nil", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// newMAC returns a GRPCMAC bound to the CryptoKeyVersion under test.
func newMAC(ctx context.Context, t *testing.T) *gcpkms.GRPCMAC {
	t.Helper()
	mac, err := gcpkms.NewGRPCMAC(macKeyName, newKMSClient(ctx, t))
	if err != nil {
		t.Fatalf("gcpkms.NewGRPCMAC() err = %v, want nil", err)
	}
	return mac
}

func TestMAC(t *testing.T) {
	mac := newMAC(t.Context(), t)

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "short_data",
			data: macData,
		},
		{
			// The largest input GRPCMAC accepts, which checks that the client-side limit agrees
			// with the one GCP KMS enforces.
			name: "max_size_data",
			data: bytes.Repeat([]byte("a"), maxMACDataSize),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tag, err := mac.ComputeMAC(tc.data)
			if err != nil {
				t.Fatalf("mac.ComputeMAC(data) err = %v, want nil", err)
			}
			if err := mac.VerifyMAC(tag, tc.data); err != nil {
				t.Errorf("mac.VerifyMAC(tag, data) err = %v, want nil", err)
			}
		})
	}
}

func TestMACIsDeterministic(t *testing.T) {
	mac := newMAC(t.Context(), t)

	// HMAC is deterministic, and both calls are pinned to the same CryptoKeyVersion, so the two
	// tags must be identical.
	tag, err := mac.ComputeMAC(macData)
	if err != nil {
		t.Fatalf("mac.ComputeMAC(data) err = %v, want nil", err)
	}
	otherTag, err := mac.ComputeMAC(macData)
	if err != nil {
		t.Fatalf("mac.ComputeMAC(data) err = %v, want nil", err)
	}
	if !bytes.Equal(otherTag, tag) {
		t.Errorf("mac.ComputeMAC(data) = %x, want %x", otherTag, tag)
	}
}

func TestMACVerifyFails(t *testing.T) {
	mac := newMAC(t.Context(), t)

	tag, err := mac.ComputeMAC(macData)
	if err != nil {
		t.Fatalf("mac.ComputeMAC(data) err = %v, want nil", err)
	}
	if len(tag) == 0 {
		t.Fatal("mac.ComputeMAC(data) = empty tag, want non-empty")
	}
	modifiedTag := bytes.Clone(tag)
	modifiedTag[0] ^= 0x01

	testCases := []struct {
		name string
		mac  []byte
		data []byte
	}{
		{
			name: "wrong_data",
			mac:  tag,
			data: macOtherData,
		},
		{
			name: "modified_mac",
			mac:  modifiedTag,
			data: macData,
		},
		{
			name: "truncated_mac",
			mac:  tag[:len(tag)-1],
			data: macData,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mac.VerifyMAC(tc.mac, tc.data)
			if err == nil {
				t.Fatalf("mac.VerifyMAC(%s, ...) err = nil, want error", tc.name)
			}
		})
	}
}

func TestMACWithContext(t *testing.T) {
	ctx := t.Context()
	mac := newMAC(ctx, t)

	tag, err := mac.ComputeMACWithContext(ctx, macData)
	if err != nil {
		t.Fatalf("mac.ComputeMACWithContext(ctx, data) err = %v, want nil", err)
	}
	if err := mac.VerifyMACWithContext(ctx, tag, macData); err != nil {
		t.Errorf("mac.VerifyMACWithContext(ctx, tag, data) err = %v, want nil", err)
	}
}
