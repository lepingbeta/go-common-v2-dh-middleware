/*
 * @Author       : Symphony zhangleping@cezhiqiu.com
 * @Date         : 2024-05-08 19:49:42
 * @LastEditors  : Symphony zhangleping@cezhiqiu.com
 * @LastEditTime : 2024-05-08 19:51:36
 * @FilePath     : /v2/go-common-v2-dh-middleware/jwt.go
 * @Description  :
 *
 * Copyright (c) 2024 by 大合前研, All Rights Reserved.
 */
package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/lepingbeta/go-common-v2-dh-http/types"
	dhlog "github.com/lepingbeta/go-common-v2-dh-log"
)

// 生成JWT Token
func JWTGenerateToken(jwtSecret, refreshSecret, userId, account string, expSec int64, refreshSec int64) (string, string, error) {
	// 设置密钥
	key := []byte(jwtSecret)

	// 创建Token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userId
	claims["account"] = account
	claims["exp"] = time.Now().Add(time.Second * time.Duration(expSec)).Unix() // 设置过期时间为7天
	// claims["exp"] = time.Now().Add(time.Minute * 1).Unix() // 设置过期时间为7天

	// 签名Token
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}

	// 创建refresh token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["user_id"] = userId
	refreshClaims["account"] = account
	// refreshClaims["exp"] = time.Now().Local().Add(time.Minute * -10).Unix() // 设置过期时间为7天
	refreshClaims["exp"] = time.Now().Add(time.Second * time.Duration(refreshSec)).Unix() // 设置过期时间为7天

	// 签名refresh token
	refreshKey := []byte(refreshSecret)
	refreshTokenString, err := refreshToken.SignedString(refreshKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshTokenString, nil
}

func JWTParseToken(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取请求头中的Token
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		// 解析Token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {

			respData := types.ResponseData{
				Status: types.ResponseStatus.Error,
				Msg:    err.Error(),
				MsgKey: "jwt_parse_token_error",
				Data:   nil,
			}
			if "Token is expired" == err.Error() {
				dhlog.Info("token 过期了")
				respData.MsgKey = "jwt_parse_token_expire"
				c.JSON(http.StatusUnauthorized, respData)
			} else {
				c.JSON(http.StatusUnauthorized, respData)
			}
			c.Abort()
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// 在这里可以获取Token中的信息，比如用户ID等
			c.Set("user_id", claims["user_id"].(string))
			c.Set("account", claims["account"].(string))
			c.Set("exp", claims["exp"])
		} else {
			respData := types.ResponseData{
				Status: types.ResponseStatus.Error,
				Msg:    err.Error(),
				MsgKey: "jwt_parse_token_failed",
				Data:   nil,
			}

			c.JSON(http.StatusUnauthorized, respData)
			c.Abort()
			return
		}
		c.Next()
	}
}
