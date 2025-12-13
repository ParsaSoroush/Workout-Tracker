package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB
var JwtSecretKey = []byte("SECRET_KEY")

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

type Workout struct {
    ID            uint       `gorm:"primaryKey"`
	Title         string     `json:"title" gorm:"not null"`
	Description   string     `json:"description"`
	Exercise      []Exercise `json:"exercise" gorm:"foreignKey:WorkoutID"`
	User          User       `gorm:"foreignKey:UserID"`
	Comments      string     `json:"comments" gorm:"foreignKey:WorkoutID"`
}

type Exercise struct {
	ID          uint   `gorm:"primaryKey"`
	Title       string `json:"title" gorm:"not null"`
	Sets        int    `jsongorm:"not null"`
	Repetitions int    `gorm:"not null"`
}

func SignUp(c *gin.Context) {
	type SignUpRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	var req SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	hashedPw, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	user := User{Username: req.Username, Password: string(hashedPw)}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(time.Minute * 1).Unix(),
	})

	tokenString, _ := token.SignedString(JwtSecretKey)

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
		"token":   tokenString,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
		},
	})
}

func SignIn(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	if err := db.Where("username = ?", input.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	// Generate JWT token for successful login (same structure as SignUp)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, _ := token.SignedString(JwtSecretKey)

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   tokenString,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
		},
	})
}

func ValidateJWTAndGetRemainingTime(c *gin.Context) (jwt.MapClaims, time.Duration, error) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		return nil, 0, errors.New("no token provided")
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return JwtSecretKey, nil
	})

	if err != nil {
		return nil, 0, err
	}

	if !token.Valid {
		return nil, 0, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, 0, errors.New("invalid token claims")
	}

	expFloat := claims["exp"].(float64)
	expTime := time.Unix(int64(expFloat), 0)

	if time.Now().After(expTime) {
		return nil, 0, errors.New("token is expired")
	}

	remaining := time.Until(expTime)

	return claims, remaining, nil
}

func AdminAddProduct(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	var input struct {
		Title string  `json:"title" binding:"required"`
		Price float64 `json:"price" binding:"required"`
		Stock int     `json:"stock" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product data"})
		return
	}

	product := Product{
		Title: input.Title,
		Price: input.Price,
		Stock: input.Stock,
	}
	if err := db.Create(&product).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create product"})
		return
	}

	c.JSON(http.StatusOK, product)
}


func connectDB() {
	dsn := "workout_user:Workout_Password$1234@tcp(localhost:3306)/workout_database?parseTime=true&loc=Local"
	dbConn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	db = dbConn
	db.AutoMigrate(&User{})
	log.Println("✅ Database connected & migrated")

}

func main() {
	connectDB()

	r := gin.Default()

	r.POST("/sign-up", SignUp)
	r.POST("/sign-in", SignIn)
	r.POST("/check", func(c *gin.Context) {
		claims, remaining, err := ValidateJWTAndGetRemainingTime(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "Token is valid",
			"remaining": remaining,
			"user": gin.H{
				"id": claims["user_id"],
				"username": claims["username"],
			},
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}