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
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"

	// Placeholder for internal proto import.
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

const (
	// signatureKeyRing is the KMS key ring hosted in the Google Cloud project
	// `tink-test-infrastructure`, used for Tink integration tests.
	signatureKeyRing = "projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/"

	// maxSignDataSize is the maximum size of the data that GRPCSigner sends to GCP KMS. Kept in
	// sync with kmsMaxSignDataSize in gcp_kms_grpc_signer.go, which is unexported.
	maxSignDataSize = 64 * 1024
)

var (
	signData      = []byte("This is some message to sign.")
	signOtherData = []byte("This is some other message.")
)

// signatureTestCase describes a GCP KMS asymmetric signing key and how Tink uses it.
type signatureTestCase struct {
	name string
	// keyName is the resource name of the CryptoKeyVersion to sign with.
	keyName string
	// publicKeyFormat is the format in which the public key must be fetched to build a verifier
	// without RPCs: GRPCVerifier parses classical keys from PEM and post-quantum keys from raw
	// NIST_PQC bytes.
	publicKeyFormat kmspb.PublicKey_PublicKeyFormat
	// requiresDataForSign reports whether GCP KMS signs the message itself rather than a digest of
	// it, in which case the client-side maxSignDataSize limit applies.
	requiresDataForSign bool
}

// keyVersionName returns the resource name of version 1 of cryptoKey. Asymmetric signing is bound
// to a specific CryptoKeyVersion, so the version is part of the name.
func keyVersionName(cryptoKey string) string {
	return signatureKeyRing + cryptoKey + "/cryptoKeyVersions/1"
}

var signatureTestCases = []signatureTestCase{
	{
		name:                "ecdsa_p256_sha256",
		keyName:             keyVersionName("signature-key"),
		publicKeyFormat:     kmspb.PublicKey_PEM,
		requiresDataForSign: false,
	},
	{
		name:                "rsa_pss_2048_sha256",
		keyName:             keyVersionName("rsa-pss-2048-key"),
		publicKeyFormat:     kmspb.PublicKey_PEM,
		requiresDataForSign: false,
	},
	{
		name:                "ml_dsa_65",
		keyName:             keyVersionName("ml-dsa-65-key"),
		publicKeyFormat:     kmspb.PublicKey_NIST_PQC,
		requiresDataForSign: true,
	},
	{
		name:                "ml_dsa_65_external_mu",
		keyName:             keyVersionName("ml-dsa-65-external-mu-key"),
		publicKeyFormat:     kmspb.PublicKey_NIST_PQC,
		requiresDataForSign: false,
	},
	{
		name:                "slh_dsa_sha2_128s",
		keyName:             keyVersionName("slh-dsa-128s-key"),
		publicKeyFormat:     kmspb.PublicKey_NIST_PQC,
		requiresDataForSign: true,
	},
}

// newSigner returns a GRPCSigner bound to the given CryptoKeyVersion.
func newSigner(ctx context.Context, t *testing.T, client *kms.KeyManagementClient, keyName string) *gcpkms.GRPCSigner {
	t.Helper()
	signer, err := gcpkms.NewGRPCSigner(ctx, keyName, client)
	if err != nil {
		t.Fatalf("gcpkms.NewGRPCSigner() err = %v, want nil", err)
	}
	return signer
}

// newVerifier returns a GRPCVerifier for the public key that GCP KMS serves for the given
// CryptoKeyVersion.
func newVerifier(ctx context.Context, t *testing.T, client *kms.KeyManagementClient, keyName string) *gcpkms.GRPCVerifier {
	t.Helper()
	verifier, err := gcpkms.NewGRPCVerifier(ctx, keyName, client)
	if err != nil {
		t.Fatalf("gcpkms.NewGRPCVerifier() err = %v, want nil", err)
	}
	return verifier
}

func TestSignVerify(t *testing.T) {
	client := newKMSClient(t.Context(), t)

	for _, tc := range signatureTestCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			signer := newSigner(ctx, t, client, tc.keyName)
			signature, err := signer.Sign(signData)
			if err != nil {
				t.Fatalf("signer.Sign(data) err = %v, want nil", err)
			}

			verifier := newVerifier(ctx, t, client, tc.keyName)
			if err := verifier.Verify(signature, signData); err != nil {
				t.Errorf("verifier.Verify(signature, data) err = %v, want nil", err)
			}
		})
	}
}

func TestVerifyFails(t *testing.T) {
	client := newKMSClient(t.Context(), t)

	for _, tc := range signatureTestCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			signer := newSigner(ctx, t, client, tc.keyName)
			signature, err := signer.Sign(signData)
			if err != nil {
				t.Fatalf("signer.Sign(data) err = %v, want nil", err)
			}
			if len(signature) == 0 {
				t.Fatal("signer.Sign(data) = empty signature, want non-empty")
			}
			verifier := newVerifier(ctx, t, client, tc.keyName)

			modifiedSignature := bytes.Clone(signature)
			modifiedSignature[len(modifiedSignature)-1] ^= 0x01

			verifyCases := []struct {
				name      string
				signature []byte
				data      []byte
			}{
				{
					name:      "modified_message",
					signature: signature,
					data:      signOtherData,
				},
				{
					name:      "modified_signature",
					signature: modifiedSignature,
					data:      signData,
				},
				{
					name:      "truncated_signature",
					signature: signature[:len(signature)-1],
					data:      signData,
				},
			}

			for _, verifyCase := range verifyCases {
				t.Run(verifyCase.name, func(t *testing.T) {
					if err := verifier.Verify(verifyCase.signature, verifyCase.data); err == nil {
						t.Errorf("verifier.Verify(%s, ...) err = nil, want error", verifyCase.name)
					}
				})
			}
		})
	}
}

func TestOfflineVerify(t *testing.T) {
	client := newKMSClient(t.Context(), t)

	for _, tc := range signatureTestCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			signer := newSigner(ctx, t, client, tc.keyName)
			signature, err := signer.Sign(signData)
			if err != nil {
				t.Fatalf("signer.Sign(data) err = %v, want nil", err)
			}

			// Fetch the public key material, then build a verifier from it without further calls
			// to GCP KMS.
			publicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
				Name:            tc.keyName,
				PublicKeyFormat: tc.publicKeyFormat,
			})
			if err != nil {
				t.Fatalf("client.GetPublicKey() err = %v, want nil", err)
			}
			verifier, err := gcpkms.NewGRPCVerifierFromPublicKey(publicKey.GetPublicKey().GetData(), publicKey.GetAlgorithm())
			if err != nil {
				t.Fatalf("gcpkms.NewGRPCVerifierFromPublicKey() err = %v, want nil", err)
			}

			if err := verifier.Verify(signature, signData); err != nil {
				t.Errorf("verifier.Verify(signature, data) err = %v, want nil", err)
			}
			if err := verifier.Verify(signature, signOtherData); err == nil {
				t.Error("verifier.Verify(signature, signOtherData) err = nil, want error")
			}
		})
	}
}

func TestSignVerifyMaxDataSize(t *testing.T) {
	client := newKMSClient(t.Context(), t)

	for _, tc := range signatureTestCases {
		t.Run(tc.name, func(t *testing.T) {
			// Only the algorithms that send the message itself to GCP KMS are subject to the
			// client-side size limit; the ones that sign a digest are not.
			if !tc.requiresDataForSign {
				t.Skip("the key signs a digest, so the limit does not apply")
			}
			maxData := bytes.Repeat([]byte("a"), maxSignDataSize)

			ctx := t.Context()
			signer := newSigner(ctx, t, client, tc.keyName)
			signature, err := signer.Sign(maxData)
			if err != nil {
				t.Fatalf("signer.Sign(maxData) err = %v, want nil", err)
			}

			verifier := newVerifier(ctx, t, client, tc.keyName)
			if err := verifier.Verify(signature, maxData); err != nil {
				t.Errorf("verifier.Verify(signature, maxData) err = %v, want nil", err)
			}
		})
	}
}

func TestSignWithContext(t *testing.T) {
	ctx := t.Context()
	client := newKMSClient(ctx, t)
	// Signing sends the same request regardless of the algorithm, so one key is enough here.
	keyName := keyVersionName("signature-key")

	signer := newSigner(ctx, t, client, keyName)
	signature, err := signer.SignWithContext(ctx, signData)
	if err != nil {
		t.Fatalf("signer.SignWithContext(ctx, data) err = %v, want nil", err)
	}

	verifier := newVerifier(ctx, t, client, keyName)
	if err := verifier.Verify(signature, signData); err != nil {
		t.Errorf("verifier.Verify(signature, data) err = %v, want nil", err)
	}
}
