package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type User struct {
	Name         string
	Email        string
	HashPassword string
}

type RegisterRequest struct {
	UserName string `json:"userName"`
	Password string `json:"passWord"`
	Email    string `json:"email"`
}

type LoginRequest struct {
	UserName string `json:"userName"`
	Password string `json:"passWord"`
}

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

var allUser = []User{}

func main() {
	// Echo instance
	e := echo.New()

	config := middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{Rate: 1, Burst: 30, ExpiresIn: 1 * time.Minute},
		),
		IdentifierExtractor: func(ctx echo.Context) (string, error) {
			id := ctx.RealIP()
			return id, nil
		},
		ErrorHandler: func(context echo.Context, err error) error {
			return context.JSON(http.StatusForbidden, nil)
		},
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return context.JSON(http.StatusTooManyRequests, "Too many request")
		},
	}

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RateLimiterWithConfig(config))

	// Routes
	// e.GET("/", Hello)
	// e.GET("/ping", Ping)
	e.POST("/user/register", Register)
	e.POST("/user/login", Login)

	// e.POST("/user/:name", AddUser)
	// e.DELETE("/user", DeleteUser)

	r := e.Group("/validate")
	restrictConfig := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(jwtCustomClaims)
		},
		SigningKey: []byte("signed key"),
	}
	r.Use(echojwt.WithConfig(restrictConfig))
	r.GET("", restricted)

	// Start server
	e.Logger.Fatal(e.Start(":8000"))
}

func Login(c echo.Context) error {
	var loginRequest LoginRequest
	if err := c.Bind(&loginRequest); err != nil {
		return err
	}

	claims := &jwtCustomClaims{
		"champ",
		"champ@mail.com",
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte("signed key"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func Register(c echo.Context) error {
	var registerRequest RegisterRequest
	if err := c.Bind(&registerRequest); err != nil {
		return err
	}

	bytes, hashErr := bcrypt.GenerateFromPassword([]byte(registerRequest.Password), 14)
	if hashErr != nil {
		return hashErr
	}

	newUser := User{
		Name:         registerRequest.UserName,
		Email:        registerRequest.Email,
		HashPassword: string(bytes),
	}

	return c.JSON(http.StatusOK, newUser)
}

func AddUser(c echo.Context) error {
	name := c.Param("name")
	fmt.Print(name)
	allUser = append(allUser, User{
		Name: name,
	})

	return c.JSON(http.StatusOK, allUser)
}

func DeleteUser(c echo.Context) error {
	name := c.QueryParam("name")

	if name == "" {
		return c.JSON(http.StatusOK, "no query")
	}

	for i, v := range allUser {
		if v.Name == name && i < len(allUser) {
			allUser = append(allUser[:i], allUser[i+1:]...)
			break
		}
	}

	return c.JSON(http.StatusOK, allUser)
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	date, _ := user.Claims.GetExpirationTime()
	// isValid := date.Unix() > time.Now().Unix()
	
	return c.JSON(http.StatusOK, echo.Map{
		"expireDate": date.UTC().Local(),
	})
}
