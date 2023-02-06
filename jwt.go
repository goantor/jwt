package jwt

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/golang-jwt/jwt"
)

var (
	Entity = &entityEs256{}
)

type OptionEs256 struct {
	PubKeyString string `yaml:"pub_key"`
	PriKeyString string `yaml:"pri_key"`

	pubKey *ecdsa.PublicKey
	priKey *ecdsa.PrivateKey
}

func (e *OptionEs256) PubKey() *ecdsa.PublicKey {
	if e.pubKey == nil {
		var err error
		e.pubKey, err = jwt.ParseECPublicKeyFromPEM(
			e.formatKey(e.PubKeyString, true),
		)

		if err != nil {
			panic(err)
		}
	}

	return e.pubKey
}

func (e *OptionEs256) PriKey() *ecdsa.PrivateKey {
	if e.priKey == nil {
		var err error
		e.priKey, err = jwt.ParseECPrivateKeyFromPEM(
			e.formatKey(e.PriKeyString, false),
		)

		if err != nil {
			panic(err)
		}
	}

	return e.priKey
}

func (e *OptionEs256) formatKey(key string, isPublic bool) []byte {
	var kind string
	if isPublic {
		kind = "PUBLIC"
	} else {
		kind = "RSA PRIVATE"
	}

	return []byte(
		fmt.Sprintf("-----BEGIN %s KEY-----\n%s\n-----END %s KEY-----", kind, key, kind),
	)
}

type entityEs256 struct {
	opt *OptionEs256
}

func (e *entityEs256) Option(opt *OptionEs256) {
	opt.PriKey()
	opt.PubKey()

	e.opt = opt
}

func (e *entityEs256) Token(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(e.opt.PriKey())
}

func (e *entityEs256) Valid(tokenString string, claims jwt.Claims) (token *jwt.Token, err error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return e.opt.PubKey(), nil
	})
}
