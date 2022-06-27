package gin_jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"io/ioutil"
)

const KeyUsageAsSignature = "sig"

// Config represents the available options for the middleware.
type Config struct {
	key          *jwk.Key
	newPkOpts    *NewKeyOptions
	importPkOpts *ImportKeyOptions
}

type Options interface {
	KeyId() string
}

// Structure used when the user generates a new private key
type NewKeyOptions struct {
	keyId string
	bits  int
}

func (o *NewKeyOptions) KeyId() string {
	return o.keyId
}

// Structure used when the user imports an existing private key
type ImportKeyOptions struct {
	keyId             string
	privateKeyPemPath string
}

func (o *ImportKeyOptions) KeyId() string {
	return o.keyId
}

// Config builder
type ConfigBuilder struct {
	config *Config
}

// New key facet of the config builder
type ConfigNewKeyBuilder struct {
	ConfigBuilder
}

func (n *ConfigBuilder) NewPrivateKey() *ConfigNewKeyBuilder {
	return &ConfigNewKeyBuilder{*n}
}

// Import key face of the config builder
type ConfigImportKeyBuilder struct {
	ConfigBuilder
}

func (n *ConfigBuilder) ImportPrivateKey() *ConfigImportKeyBuilder {
	return &ConfigImportKeyBuilder{*n}
}

// Initialise a new config builder
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{config: &Config{}}
}

// Initiate the import opts obj if nil
func (n *ConfigImportKeyBuilder) initiateImportOptsIfNil() {
	if n.config.importPkOpts == nil {
		n.config.importPkOpts = &ImportKeyOptions{}
	}
}

// Add the private key path
func (n *ConfigImportKeyBuilder) WithPath(privateKeyPemPath string) *ConfigImportKeyBuilder {
	n.initiateImportOptsIfNil()
	n.config.importPkOpts.privateKeyPemPath = privateKeyPemPath
	return n
}

// Add a key id to the private key
func (n *ConfigImportKeyBuilder) WithKeyId(keyId string) *ConfigImportKeyBuilder {
	n.initiateImportOptsIfNil()
	n.config.importPkOpts.keyId = keyId
	return n
}

// Initiate the new opts obj if nil
func (n *ConfigNewKeyBuilder) initiateNewOptsIfNil() {
	if n.config.newPkOpts == nil {
		n.config.newPkOpts = &NewKeyOptions{}
	}
}

// Add the key length
func (n *ConfigNewKeyBuilder) WithKeyLength(bits int) *ConfigNewKeyBuilder {
	n.initiateNewOptsIfNil()
	n.config.newPkOpts.bits = bits
	return n
}

// Add a key id to the private key
func (n *ConfigNewKeyBuilder) WithKeyId(keyId string) *ConfigNewKeyBuilder {
	n.initiateNewOptsIfNil()
	n.config.newPkOpts.keyId = keyId
	return n
}

// Build the config object in order to initiate the middleware
func (b *ConfigBuilder) Build() (*Config, error) {
	var key jwk.Key
	var opts Options
	var err error
	if b.config.newPkOpts != nil && b.config.importPkOpts != nil {
		return nil, fmt.Errorf("cannot import and generate a new private key")
	}

	// generate a new private key
	if b.config.newPkOpts != nil {
		newPkOpts := b.config.newPkOpts
		key, err = generatePrivateKey(*newPkOpts)
		if err != nil {
			return nil, fmt.Errorf("cannot generate new private key %v", err)
		}
		opts = newPkOpts
	}

	// import the private key
	if b.config.importPkOpts != nil {
		importPkOpts := b.config.importPkOpts
		key, err = importPrivateKey(*importPkOpts)
		if err != nil {
			return nil, fmt.Errorf("cannot import private key %v", err)
		}
		opts = importPkOpts
	}

	if key == nil {
		return nil, fmt.Errorf("generate or import a private key")
	}

	// add an id to the certificate according to RFC
	err = key.Set(jwk.KeyIDKey, opts.KeyId())
	if err != nil {
		return nil, fmt.Errorf("cannot add an id property to the private key %v", err)
	}

	err = key.Set(jwk.KeyUsageKey, KeyUsageAsSignature)
	if err != nil {
		return nil, fmt.Errorf("cannot add an id property to the private key %v", err)
	}

	// cast to private key
	if _, ok := key.(jwk.RSAPrivateKey); !ok {
		return nil, fmt.Errorf("expected jwk.SymmetricKey, got %T", key)
	}

	// generate public key
	_, err = key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create public key %v", err)
	}

	b.config.key = &key

	return b.config, nil
}

// Generate a private key
func generatePrivateKey(opts NewKeyOptions) (jwk.Key, error) {
	rawPrivateKey, err := rsa.GenerateKey(rand.Reader, opts.bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new RSA private key: %s\n", err)
	}

	key, err := jwk.FromRaw(rawPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric key: %s\n", err)
	}

	return key, nil
}

// Import a private key with pem format
func importPrivateKey(opts ImportKeyOptions) (jwk.Key, error) {
	// import from path
	keyData, err := ioutil.ReadFile(opts.privateKeyPemPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key %v", err)
	}

	// check if it's a PEM file
	key, err := jwk.ParseKey(keyData, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key %v", err)
	}

	return key, nil
}

// Refer to rfc for more information: https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1
type JkwsResponse struct {
	KeyTypeKey        string `json:"kty"`
	AlgorithmKey      string `json:"alg"`
	PubKeyExponentKey string `json:"e"`
	PubKeyModulusKey  string `json:"n"`
	KeyUsageKey       string `json:"use"`
	KeyIDKey          string `json:"kid"`
}

// Jkws middleware exposing the public key properties required in order to decrypt
// a jwt token
func Jkws(config Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// get private key and its properties
		key := *config.key

		// get public key
		pubKey, _ := key.PublicKey()

		// get public key exponent
		E, _ := key.Get("e")
		// get public key modulus
		N, _ := key.Get("n")

		// generate jkws response
		res := JkwsResponse{
			KeyTypeKey:        pubKey.KeyType().String(),
			AlgorithmKey:      jwa.RS256.String(),
			PubKeyExponentKey: EncodeToString(E.([]byte)),
			PubKeyModulusKey:  EncodeToString(N.([]byte)),
			KeyUsageKey:       key.KeyUsage(),
			KeyIDKey:          key.KeyID(),
		}

		// expose jkws response
		c.JSON(200, gin.H{
			"keys": []JkwsResponse{res},
		})
	}
}

// EncodeToString utility which converts []byte into a base64 string
func EncodeToString(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}
