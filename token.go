package jwt_token_package

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// KEY Слово-секрет, нужен для расшифровки токена
var KEY = []byte("secret")

// TOKEN_TIME Время жизни токена, срок годности
var TOKEN_TIME int64 = 100

// SignJWT Метод создания токена
func SignJWT(userId int) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// Создаем payload структуру
		"userId":      userId,                         // UserId для идентификации пользователя
		"expiredTime": time.Now().Unix() + TOKEN_TIME, // expiredTime для безопасности
	}).SignedString(KEY)
	if err != nil {
		return ""
	}
	return token
}

// GetIdentity Расшифровываем токен и получаем из него данные (identity)
func GetIdentity(token string) map[string]interface{} {
	identity, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return KEY, nil
	})
	if err != nil {
		panic(err)
	}
	// Возвращаем мапу с payload пользователя
	return identity.Claims.(jwt.MapClaims)
}

// RefreshToken Обновляем токен на основе данных со старого просроченного токена
func RefreshToken(token string) string {
	return SignJWT(int(GetIdentity(token)["user_id"].(float64)))
}
