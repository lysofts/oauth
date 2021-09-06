package auth

import "github.com/golang-jwt/jwt"

//User is the model that defines auth users saved in database
type User struct {
	UID          string `json:"uid,omitempty" bson:"_id"`
	FirstName    string `json:"firstName,omitempty" validate:"required, min=2, max=100" bson:"firstName"`
	LastName     string `json:"lastName,omitempty" validate:"required, min=2, max=100" bson:"lastName"`
	Email        string `json:"email,omitempty" validate:"email, required"`
	Password     string `json:"password,omitempty"`
	Phone        string `json:"phone,omitempty" validate:"required"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty" bson:"refreshToken"`
	CreatedAt    int64  `json:"createdAt,omitempty" bson:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt,omitempty" bson:"updatedAt"`
}

// SignedDetails are jwt details create by jwt
type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	UID       string
	jwt.StandardClaims
}
