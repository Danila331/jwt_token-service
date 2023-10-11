package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const secretKey = "mama i teby lublu"

func CreateJWTtoken(user_id string) (string, error) {
	// кодируем токен
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": user_id,
		"exp": time.Now().Add(time.Minute * 10).Unix(),
	})
	// подписываем токен
	tokenstring, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenstring, nil
}

func DecodeJWTtoken(tokenstring string) (string, error) {
	// Проверяем правильный ли у нас формат кодирования токена
	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("method: %v", token.Header["alg"])
		}
		// возвращаем секретный ключ для подписания токена
		return []byte(secretKey), nil
	})
	if err != nil {
		return "", err
	}
	// Проверка токена на валидность
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userId := claims["sub"].(string)
		return userId, nil
	}

	return "", fmt.Errorf("invalid token")
}

func RefreschJWTtoken(tokenstring string) (string, error) {
	// Проверяем правильный ли у нас формат кодирования токена
	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("method: %v", token.Header["alg"])
		}
		// Возр=вращаем секретный ключ для подписания токена
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", err
	}

	// Проверяем истекло ли время пора ли менять токен и на валидность токена
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if time.Unix(int64(claims["exp"].(float64)), 0).Sub(time.Now()) > 10*time.Minute {
			return "", fmt.Errorf("token is not expired or too early to refresh")
		}

		userId := claims["sub"].(string)

		newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": userId,
			"exp": time.Now().Add(time.Minute * 10).Unix(),
		})

		tokenString, err := newToken.SignedString([]byte(secretKey))
		if err != nil {
			return "", err
		}

		return tokenString, nil
	}

	return "", fmt.Errorf("invalid token")
}
