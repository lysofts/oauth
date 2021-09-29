package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//AuthMidleware is the authentication middleware for basic jwt authentication
func AuthMidleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqToken := c.Request.Header.Get("Authorization")

		if reqToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		splitToken := strings.Split(reqToken, " ")
		if len(splitToken) != 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid auth token provided"})
			c.Abort()
			return
		}

		reqToken = splitToken[1]
		claims, err := ValidateToken(reqToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
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
