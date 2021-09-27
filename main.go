package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	databaseutils "github.com/lysofts/database-utils"
	"github.com/lysofts/profileutils"
)

//valid is the validator used to validate input data
var valid = validator.New()

//Auth is the authentication object that implements jwt
type Auth struct {
	ctx            context.Context
	collectionName string
	db             *databaseutils.Database
}

//NewAuth initializes the Auth
func NewAuth(ctx context.Context, db *databaseutils.Database, collectionName string) *Auth {
	return &Auth{
		ctx:            ctx,
		collectionName: collectionName,
		db:             db,
	}
}

// GenerateAllTokens generates both the detailed token and refresh token
func (a Auth) GenerateAllTokens(email string, firstName string, lastName string, uid string) (signedToken string, signedRefreshToken string, err error) {
	claims := profileutils.SignedDetails{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		UID:       uid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	refreshClaims := profileutils.SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

//UpdateAllTokens renews the user tokens when they login
func (a Auth) UpdateAllTokens(ctx context.Context, signedToken string, signedRefreshToken string, userId string) error {
	updatedAt := time.Now().Unix()

	updateObj := map[string]interface{}{
		"token":        signedToken,
		"refreshToken": signedRefreshToken,
		"updatedAt":    updatedAt,
	}

	filter := map[string]interface{}{"_id": userId}

	_, err := a.db.Update(ctx, a.collectionName, filter, updateObj)

	if err != nil {
		return err
	}

	return nil
}

//SignUp creates a user account using provided details
func (a Auth) SignUp(ctx context.Context, input SignUpInput) (*AuthResponse, error) {
	err := valid.Struct(input)
	if err != nil {
		return nil, err
	}

	users, err := a.db.Read(ctx, a.collectionName, map[string]interface{}{"phone": input.Phone})
	if err != nil {
		return nil, err
	}

	if len(users) > 0 {
		return nil, fmt.Errorf("a user with this phone number `%v` already exists", input.Phone)
	}

	users, err = a.db.Read(ctx, a.collectionName, map[string]interface{}{"email": input.Email})
	if err != nil {
		return nil, err
	}

	if len(users) > 0 {
		return nil, fmt.Errorf("a user with this email `%v` already exists", input.Email)
	}

	password, err := HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	uid := uuid.NewString()

	token, refreshToken, _ := a.GenerateAllTokens(input.Email, input.FirstName, input.LastName, uid)

	user := profileutils.User{
		UID:          uid,
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		Email:        input.Email,
		Password:     *password,
		Phone:        input.Phone,
		Token:        token,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}

	_, err = a.db.Create(ctx, a.collectionName, user)

	if err != nil {
		return nil, fmt.Errorf("unable to create a user profile: %v", err)
	}

	resp := AuthResponse{
		UID:          user.UID,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
	}
	return &resp, nil
}

//Login authenticates a user with existing user account
func (a Auth) Login(ctx context.Context, input LoginInput) (*AuthResponse, error) {
	err := valid.Struct(input)
	if err != nil {
		return nil, err
	}

	users, err := a.db.ReadOne(ctx, a.collectionName, map[string]interface{}{"email": input.Email})
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("a user with this email %v not found", input.Email)
	}

	user := profileutils.User{}

	res, err := a.db.ReadOne(ctx, a.collectionName, map[string]interface{}{"email": input.Email})
	if err != nil {
		return nil, err
	}

	byteData, _ := json.Marshal(res)
	err = json.Unmarshal(byteData, &user)
	if err != nil {
		return nil, fmt.Errorf("error unable to get user: %v", err)
	}

	valid, err := VerifyPassword(user.Password, input.Password)
	if err != nil {
		return nil, fmt.Errorf("unable to verify password: %v", err)
	}

	if !valid {
		return nil, fmt.Errorf("invalid login password")
	}

	token, refreshToken, err := a.GenerateAllTokens(input.Email, user.FirstName, user.LastName, user.UID)
	if err != nil {
		return nil, fmt.Errorf("could not generate auth tokens: %v", err)
	}

	err = a.UpdateAllTokens(ctx, token, refreshToken, user.UID)

	if err != nil {
		return nil, fmt.Errorf("could not update auth tokens: %v", err)
	}

	resp := AuthResponse{
		UID:          user.UID,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
	}

	return &resp, nil
}

//AuthMidleware is the authentication middleware for basic jwt authentication
func (a Auth) AuthMidleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqToken := c.Request.Header.Get("Authorization")
		splitToken := strings.Split(reqToken, "Bearer")
		reqToken = splitToken[1]

		if reqToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		claims, err := ValidateToken(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("firstName", claims.FirstName)
		c.Set("lastName", claims.LastName)
		c.Set("uid", claims.UID)

		c.Next()

	}
}
