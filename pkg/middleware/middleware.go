package middleware

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

func validateToken(c *gin.Context, pem []byte) (*jwt.Token, error) {
	authHeader := c.GetHeader("Authorization")
	authHeader = strings.Replace(authHeader, "Bearer ", "", -1)

	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(pem)

	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	return jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
		audiences, ok := token.Claims.(jwt.MapClaims)["aud"].([]interface{})
		if !ok {
			return nil, errors.New("failed to map audiences")
		}

		for _, audience := range audiences {
			if audience == os.Getenv("AUDIENCE") {
				return rsaKey, nil
			}
		}

		return nil, errors.New("failed to validate token")
	})
}

func Authenticate(pem []byte) gin.HandlerFunc {
	return func(c *gin.Context) {

		_, err := validateToken(c, pem)

		if err != nil {
			log.Error(err.Error())
			c.AbortWithStatus(401)
			return
		}

		c.Next()
	}
}

// Authorize with scopes
func Authorize(pem []byte, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {

		token, err := validateToken(c, pem)

		if err != nil {
			log.Error(err.Error())
			c.AbortWithStatus(401)
			return
		}

		permissionsString, ok := token.Claims.(jwt.MapClaims)["scope"].(interface{}).(string)

		permissions := strings.Split(permissionsString, " ")

		if !ok {
			c.AbortWithStatus(403)
			return
		}

		for _, permission := range permissions {
			if permission == scope {
				c.Next()
				return
			}
		}

		c.AbortWithStatus(403)
	}
}
