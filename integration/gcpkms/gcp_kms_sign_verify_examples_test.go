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
	"context"
	"log"

	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"  // injected by Copybara
	// Placeholder for internal proto import.
)

// ExampleNewGRPCSigner demonstrates how to create and use a GCP KMS gRPC signer. This fetches the
// public key from GCP KMS once, to determine the signing algorithm.
func ExampleNewGRPCSigner() {
	ctx := context.Background()

	// Replace keyName with your actual GCP KMS key version name.
	const keyName = "projects/my-project/locations/global/keyRings/my-key-ring/cryptoKeys/my-key/cryptoKeyVersions/1"

	// Replace "/mysecurestorage/credentials.json" with actual path or other auth method if needed for a real run.
	credentialsOpt := option.WithAuthCredentialsFile(option.ServiceAccount, "/mysecurestorage/credentials.json")

	// Create a GCP KMS client for the asymmetric signing API.
	kmsClient, err := kms.NewKeyManagementClient(ctx, credentialsOpt)
	if err != nil {
		log.Fatalf("kms.NewKeyManagementClient failed: %v", err)
	}
	defer kmsClient.Close()

	// Create a signer bound to the given key version.
	signer, err := gcpkms.NewGRPCSigner(ctx, keyName, kmsClient)
	if err != nil {
		log.Fatalf("gcpkms.NewGRPCSigner failed: %v", err)
	}

	// Sign the data. The private key never leaves GCP KMS: each Sign call sends the data or a
	// digest of the data to GCP KMS.
	data := []byte("data to sign")
	signature, err := signer.Sign(data)
	if err != nil {
		log.Fatalf("signer.Sign failed: %v", err)
	}

	// The signature can now be stored or transmitted, and later checked with a verifier built by
	// gcpkms.NewGRPCVerifier.
	_ = signature
}

// ExampleNewGRPCVerifier demonstrates how to create and use a GCP KMS gRPC verifier.
func ExampleNewGRPCVerifier() {
	ctx := context.Background()

	// Replace keyName with your actual GCP KMS key version name.
	const keyName = "projects/my-project/locations/global/keyRings/my-key-ring/cryptoKeys/my-key/cryptoKeyVersions/1"

	// Replace "/mysecurestorage/credentials.json" with actual path or other auth method if needed for a real run.
	credentialsOpt := option.WithAuthCredentialsFile(option.ServiceAccount, "/mysecurestorage/credentials.json")

	// Create a GCP KMS client for the asymmetric signing API.
	kmsClient, err := kms.NewKeyManagementClient(ctx, credentialsOpt)
	if err != nil {
		log.Fatalf("kms.NewKeyManagementClient failed: %v", err)
	}
	defer kmsClient.Close()

	// Create a verifier bound to the given key version. gcpkms.NewGRPCVerifier fetches the public
	// key from GCP KMS once; all subsequent verification is performed locally, with no further KMS
	// calls.
	verifier, err := gcpkms.NewGRPCVerifier(ctx, keyName, kmsClient)
	if err != nil {
		log.Fatalf("gcpkms.NewGRPCVerifier failed: %v", err)
	}

	// data and signature were produced earlier by a signer for the same key version; see
	// gcpkms.NewGRPCSigner.
	data := []byte("data to sign")
	var signature []byte

	// Verify returns nil if signature is a valid signature of data, and a non-nil error otherwise.
	if err := verifier.Verify(signature, data); err != nil {
		log.Fatalf("verifier.Verify failed: %v", err)
	}
}

const examplePublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYP7UuiVanTHJYet0xjVtaMBJuJI7
Yfps5mliLmDyn7Z5A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQ==
-----END PUBLIC KEY-----`

func loadSavedPublicKey() []byte {
	return []byte(examplePublicKey)
}

// ExampleNewGRPCVerifierFromPublicKey demonstrates how to create and use a GCP KMS gRPC verifier
// from pre-fetched public key material, without contacting GCP KMS.
func ExampleNewGRPCVerifierFromPublicKey() {
	// pemPublicKey is an example PEM-encoded ECDSA P-256 public key as returned by GCP KMS.
	// In a real application, this material could be loaded from a file, configuration, or cache.
	pemPublicKey := loadSavedPublicKey()

	// Create a verifier from the pre-fetched public key material and matching algorithm.
	// This does not make any calls to GCP KMS.
	verifier, err := gcpkms.NewGRPCVerifierFromPublicKey(pemPublicKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
	if err != nil {
		log.Fatalf("gcpkms.NewGRPCVerifierFromPublicKey failed: %v", err)
	}

	// data and signature were produced earlier by a signer for the same key version; see
	// gcpkms.NewGRPCSigner.
	data := []byte("data to sign")
	var signature []byte

	// Verify returns nil if signature is a valid signature of data, and a non-nil error otherwise.
	if err := verifier.Verify(signature, data); err != nil {
		log.Fatalf("verifier.Verify failed: %v", err)
	}
}
