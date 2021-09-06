package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

//SECRET_KEY
var SECRET_KEY string = os.Getenv("AUTH_SECRET_KEY")

//HashPassword is used to encrypt the password before it is stored in the DB
func HashPassword(password string) (*string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return nil, fmt.Errorf("unable to hash password: %v", err)
	}
	resp := string(bytes)
	return &resp, nil
}

//VerifyPassword checks the input password while verifying it with the passward in the DB.
func VerifyPassword(userPassword string, providedPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(providedPassword))

	if err != nil {
		return false, err
	}

	return true, nil
}

//ValidateToken validates the jwt token
func ValidateToken(signedToken string) (claims *SignedDetails, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		err = fmt.Errorf("the token is invalid")
		return nil, err
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = fmt.Errorf("the token is expired")
		return nil, err
	}

	return claims, nil
}
