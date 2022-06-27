# gin-jwks [![Go Report Card](https://goreportcard.com/badge/github.com/v4lproik/gin-jwks)](https://goreportcard.com/report/github.com/v4lproik/gin-jwks) [![CircleCI](https://dl.circleci.com/status-badge/img/gh/v4lproik/gin-jwks/tree/main.svg?style=shield)](https://dl.circleci.com/status-badge/redirect/gh/v4lproik/gin-jwks/tree/main)
This gin-gonic handler aims at providing a JKMS exposing the public key properties needed in the JWT encryption/decryption workflow using asymmetric cryptography.
## Usage
### Import your own private key
```go
func main() {
    r := gin.Default()

    builder := NewConfigBuilder()
    config, err := builder.
        ImportPrivateKey().
        WithPath("../testdata/private.pem").
        WithKeyId("my-id").
        Build()

    if err != nil {
        fmt.Errorf("error generating conf %v", err)
    }

    r.GET("/", Jkws(*config))
    r.Run()
}
```
### Generate a private key
```go
func main() {
    r := gin.Default()

    builder := NewConfigBuilder()
    config, err := builder.
        NewPrivateKey().
        WithKeyId("my-id").
        WithKeyLength(2048).
        Build()

    if err != nil {
        fmt.Errorf("error generating conf %v", err)
        return
    }

    r.GET("/", Jkws(*config))
    r.Run()
}
```
### Output
```bash
{
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "e": "AQAB",
            "n": "6DGyBMjYcC5nf7eHHCqvwdgjr5_6_AnMbV124jtszu62vnMHHSIkVP6e5FWEQRUWXYww2cu-PKV2cJ1PcSvIs-OTwSayJnrQThsK5PzEAsH8pEhAoC2Izlpv4oK7vJYoUulcWTLFq0TcC0GkIZ3rUUn2RRAq508A0FI-ep17PjU7yamZAHwlfZPQ6NEFOnabBUE-qCaquv1PmNXV-PLZhhwAxkuxcGiZCaflkNmH8mw7L79zQWVAVgyIS68OV7CnblbuNwCOOzuLmnEJD3pwCfMq7a22vW_HXfVWzRqehkfgvH2Dmakbfm17WzFaWo_a8AUaU8ojY8DK-YxV0pU0ow",
            "use": "sig",
            "kid": "my-id"
        }
    ]
}
```
