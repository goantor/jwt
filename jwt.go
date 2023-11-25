package jwt

import (
	"crypto/ecdsa"
	"github.com/golang-jwt/jwt"
)

type IEcdsaOption interface {
	PubKey() *ecdsa.PublicKey
	PriKey() *ecdsa.PrivateKey
}

type IJwt interface {
	Token(claims jwt.Claims) (string, error)
	Valid(tokenString string, claims jwt.Claims) (token *jwt.Token, err error)
}

//type entityEs256 struct {
//	opt *OptionEs256
//}

type es256Jwt struct {
	opt IEcdsaOption
}

func NewEs256Jwt(opt IEcdsaOption) IJwt {
	return &es256Jwt{
		opt: opt,
	}
}

func (e *es256Jwt) Token(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(e.opt.PriKey())
}

func (e *es256Jwt) Valid(tokenString string, claims jwt.Claims) (token *jwt.Token, err error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return e.opt.PubKey(), nil
	})
}
