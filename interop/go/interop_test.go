// Cross-checks with agilecrypto (the Rust implementation of the citius C
// API), run by `cargo xtask interop` in citius-rust. This file is not part of
// citius-server: the task places it into internal/provider/software with
// `go test -overlay`, so it can call the real software provider without
// changing that repository.
//
// It reads rust.json from $AGC_INTEROP_DIR, verifies and decrypts every
// case with the Go provider, and writes go.json: the same operations made
// here, for the Rust side to check. Metadata is built as the citius-server
// handlers build it.
package software_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	metapb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

type interopCase struct {
	Template        string  `json:"template"`
	Kind            string  `json:"kind"`
	Algorithm       string  `json:"algorithm"`
	Private         string  `json:"private"`
	PrivateEncoding string  `json:"private_encoding"`
	Public          string  `json:"public"`
	PublicEncoding  string  `json:"public_encoding"`
	Context         *string `json:"context"`
	Input           string  `json:"input"`
	Hash            int32   `json:"hash"`
	Aad             *string `json:"aad"`
	Artifact        string  `json:"artifact"`
	ProviderOutput  string  `json:"provider_output"`
	Metadata        string  `json:"metadata"`
}

type interopVectors struct {
	Producer string        `json:"producer"`
	Cases    []interopCase `json:"cases"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func optHex(t *testing.T, s *string) []byte {
	if s == nil {
		return nil
	}
	return unhex(t, *s)
}

var privateEncodings = map[string]providerpb.PrivateKeyEncoding{
	"PKCS8": providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
	"SEC1":  providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1,
	"RAW":   providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW,
}

var publicEncodings = map[string]providerpb.PublicKeyEncoding{
	"SPKI": providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI,
	"RAW":  providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW,
}

func nameOf[E comparable](m map[string]E, e E) string {
	for k, v := range m {
		if v == e {
			return k
		}
	}
	return ""
}

func mustMarshal(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return hex.EncodeToString(b)
}

// checkRust verifies or decrypts one Rust case with the Go provider.
func checkRust(t *testing.T, p *software.Provider, c interopCase) error {
	ctx := context.Background()
	alg := &api.AlgorithmDetails{}
	if err := proto.Unmarshal(unhex(t, c.Algorithm), alg); err != nil {
		return fmt.Errorf("algorithm: %w", err)
	}
	out := &metapb.ProviderOutput{}
	if err := proto.Unmarshal(unhex(t, c.ProviderOutput), out); err != nil {
		return fmt.Errorf("provider output: %w", err)
	}
	md := &metapb.OperationMetadata{}
	if err := proto.Unmarshal(unhex(t, c.Metadata), md); err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	wantHash := api.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	if c.Kind == "digest_sign" {
		wantHash = api.HashAlgorithm(c.Hash)
	}
	if md.GetKeyVersion() != 1 || md.GetApiVersion() != "2.0" || md.GetUserContext()["tenant"] != "acme" ||
		md.GetDigestHash() != wantHash || !proto.Equal(md.GetProviderOutput(), out) {
		return fmt.Errorf("metadata decoded to %v", md)
	}

	input, artifact := unhex(t, c.Input), unhex(t, c.Artifact)
	tampered := append([]byte(nil), artifact...)
	tampered[len(tampered)-1] ^= 1
	switch c.Kind {
	case "sign":
		verify := func(sig []byte) (bool, error) {
			req := &providerpb.VerifyRequest{
				KeyMaterial: unhex(t, c.Public), Input: input, Signature: sig, Algorithm: alg, Output: out,
				KeyMaterialEncoding: publicEncodings[c.PublicEncoding],
				ScopeParams:         &providerpb.VerifyRequest_NoContext{NoContext: &api.NoParams{}},
			}
			if c.Context != nil {
				req.ScopeParams = &providerpb.VerifyRequest_DomainContext{
					DomainContext: &api.SignatureDomainContext{Context: optHex(t, c.Context)}}
			}
			r, err := p.Verify(ctx, req)
			return r.GetValid(), err
		}
		return checkVerify(verify, artifact, tampered)
	case "digest_sign":
		verify := func(sig []byte) (bool, error) {
			r, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
				KeyMaterial: unhex(t, c.Public), Digest: input, Signature: sig, Algorithm: alg, Output: out,
				HashAlgorithm:       api.HashAlgorithm(c.Hash),
				KeyMaterialEncoding: publicEncodings[c.PublicEncoding],
				ScopeParams:         &providerpb.VerifyDigestRequest_NoContext{NoContext: &api.NoParams{}},
			})
			return r.GetValid(), err
		}
		return checkVerify(verify, artifact, tampered)
	default:
		req := &providerpb.DecryptRequest{
			KeyMaterial: unhex(t, c.Private), Ciphertext: artifact, Output: out, Algorithm: alg,
			KeyMaterialEncoding: privateEncodings[c.PrivateEncoding],
			ScopeParams:         &providerpb.DecryptRequest_NoParams{NoParams: &api.NoParams{}},
		}
		if c.Aad != nil {
			req.ScopeParams = &providerpb.DecryptRequest_AeadParams{AeadParams: &api.AeadEncryptParams{Aad: optHex(t, c.Aad)}}
		}
		r, err := p.Decrypt(ctx, req)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		if string(r.GetPlaintext()) != string(input) {
			return fmt.Errorf("decrypts to something else")
		}
		return nil
	}
}

func checkVerify(verify func([]byte) (bool, error), sig, tampered []byte) error {
	ok, err := verify(sig)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return fmt.Errorf("the signature does not verify")
	}
	if ok, _ := verify(tampered); ok {
		return fmt.Errorf("a tampered signature verifies")
	}
	return nil
}

// produce makes the same operation as c with a key Go generates.
func produce(t *testing.T, p *software.Provider, c interopCase) (interopCase, error) {
	ctx := context.Background()
	alg := &api.AlgorithmDetails{}
	if err := proto.Unmarshal(unhex(t, c.Algorithm), alg); err != nil {
		return c, err
	}
	key, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		return c, fmt.Errorf("generate: %w", err)
	}
	g := c
	g.Private = hex.EncodeToString(key.GetKeyMaterial())
	g.PrivateEncoding = nameOf(privateEncodings, key.GetKeyMaterialEncoding())
	g.Public = hex.EncodeToString(key.GetPublicKeyBytes())
	g.PublicEncoding = nameOf(publicEncodings, key.GetPublicKeyEncoding())
	input := unhex(t, c.Input)

	var artifact []byte
	var out *metapb.ProviderOutput
	md := &metapb.OperationMetadata{KeyVersion: 1}
	switch c.Kind {
	case "sign":
		req := &providerpb.SignRequest{
			KeyMaterial: key.GetKeyMaterial(), Input: input, Algorithm: alg,
			KeyMaterialEncoding: key.GetKeyMaterialEncoding(),
			ScopeParams:         &providerpb.SignRequest_NoContext{NoContext: &api.NoParams{}},
		}
		if c.Context != nil {
			req.ScopeParams = &providerpb.SignRequest_DomainContext{
				DomainContext: &api.SignatureDomainContext{Context: optHex(t, c.Context)}}
		}
		r, err := p.Sign(ctx, req)
		if err != nil {
			return c, fmt.Errorf("sign: %w", err)
		}
		artifact, out = r.GetSignature(), r.GetOutput()
	case "digest_sign":
		r, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
			KeyMaterial: key.GetKeyMaterial(), Digest: input, Algorithm: alg,
			HashAlgorithm:       api.HashAlgorithm(c.Hash),
			KeyMaterialEncoding: key.GetKeyMaterialEncoding(),
			ScopeParams:         &providerpb.SignDigestRequest_NoContext{NoContext: &api.NoParams{}},
		})
		if err != nil {
			return c, fmt.Errorf("sign digest: %w", err)
		}
		artifact, out = r.GetSignature(), r.GetOutput()
		// As the DigestSign handler does.
		md.DigestHash = api.HashAlgorithm(c.Hash)
	default:
		req := &providerpb.EncryptRequest{
			KeyMaterial: key.GetKeyMaterial(), Plaintext: input, Algorithm: alg,
			KeyMaterialEncoding: key.GetKeyMaterialEncoding(),
			ScopeParams:         &providerpb.EncryptRequest_NoParams{NoParams: &api.NoParams{}},
		}
		if c.Aad != nil {
			req.ScopeParams = &providerpb.EncryptRequest_AeadParams{AeadParams: &api.AeadEncryptParams{Aad: optHex(t, c.Aad)}}
		}
		r, err := p.Encrypt(ctx, req)
		if err != nil {
			return c, fmt.Errorf("encrypt: %w", err)
		}
		artifact, out = r.GetCiphertext(), r.GetOutput()
	}
	md.ProviderOutput = out
	g.Artifact = hex.EncodeToString(artifact)
	g.ProviderOutput = mustMarshal(t, out)
	g.Metadata = mustMarshal(t, md)
	return g, nil
}

func TestRustInterop(t *testing.T) {
	dir := os.Getenv("AGC_INTEROP_DIR")
	if dir == "" {
		t.Skip("AGC_INTEROP_DIR is not set: run `cargo xtask interop` in citius-rust")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "rust.json"))
	if err != nil {
		t.Fatal(err)
	}
	var in interopVectors
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	p := software.New()
	result := interopVectors{Producer: "citius-server software provider"}
	for _, c := range in.Cases {
		name := c.Template + "/" + c.Kind
		if c.Context != nil {
			name += "+context"
		}
		if err := checkRust(t, p, c); err != nil {
			t.Errorf("rust %s: %v", name, err)
		}
		g, err := produce(t, p, c)
		if err != nil {
			t.Errorf("go %s: %v", name, err)
			continue
		}
		result.Cases = append(result.Cases, g)
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d Rust cases checked, %d Go cases written", len(in.Cases), len(result.Cases))
}
