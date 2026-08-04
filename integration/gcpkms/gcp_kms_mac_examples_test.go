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
)

// ExampleNewGRPCMAC demonstrates how to create and use a GCP KMS gRPC MAC.
func ExampleNewGRPCMAC() {
	ctx := context.Background()

	// Replace keyName with your actual GCP KMS key version name.
	const keyName = "projects/my-project/locations/global/keyRings/my-key-ring/cryptoKeys/my-key/cryptoKeyVersions/1"

	// Replace "/mysecurestorage/credentials.json" with actual path or other auth method if needed for a real run.
	credentialsOpt := option.WithAuthCredentialsFile(option.ServiceAccount, "/mysecurestorage/credentials.json")

	// Create a GCP KMS client for the MAC API.
	kmsClient, err := kms.NewKeyManagementClient(ctx, credentialsOpt)
	if err != nil {
		log.Fatalf("kms.NewKeyManagementClient failed: %v", err)
	}
	defer kmsClient.Close()

	// Create a MAC bound to the given key version.
	mac, err := gcpkms.NewGRPCMAC(keyName, kmsClient)
	if err != nil {
		log.Fatalf("gcpkms.NewGRPCMAC failed: %v", err)
	}

	// Compute a MAC over the data.
	data := []byte("data to authenticate")
	tag, err := mac.ComputeMAC(data)
	if err != nil {
		log.Fatalf("mac.ComputeMAC failed: %v", err)
	}

	// Verify the tag against the data. VerifyMAC returns nil if tag is a valid MAC of data, and a
	// non-nil error otherwise.
	if err := mac.VerifyMAC(tag, data); err != nil {
		log.Fatalf("mac.VerifyMAC failed: %v", err)
	}
}
