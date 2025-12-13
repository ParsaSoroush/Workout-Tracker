package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
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
	ID        uint   	 `gorm:"primaryKey"`
	Username  string     `gorm:"unique;not null"`
	Password  string     `gorm:"not null"`
	CretaedAt time.Time
	Workouts []Workout
}

type Workout struct {
	ID          uint       `gorm:"primaryKey"`
	Title       string     `json:"title" gorm:"not null"`
	Description string     `json:"description"`
	Comments    string     `json:"comments" default:""`
	CretaedAt   time.Time

	UserID      uint       `gorm:"not null"`
	User        User

	Exercises []Exercise `json:"exercise" gorm:"constraint:OnDelete:CASCADE;"`
}

type Exercise struct {
	ID          uint   `gorm:"primaryKey"`
	Title       string `json:"title" gorm:"not null"`
	Sets        int    `json:"sets" gorm:"not null"`
	Repetitions int    `json:"repetitions" gorm:"not null"`

	WorkoutID uint `gorm:"not null"`
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
		"exp":      time.Now().Add(time.Minute * 5).Unix(),
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

func AddExercise(c *gin.Context) {
	workoutIDParam := c.Param("workout_id")
	workoutID, err := strconv.ParseUint(workoutIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid workout ID"})
		return
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	userID := uint(claims["user_id"].(float64))

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", uint(workoutID), userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Workout not found or access denied"})
		return
	}

	var input struct {
		Title       string `json:"title" binding:"required"`
		Sets        int    `json:"sets" binding:"required"`
		Repetitions int    `json:"repetitions" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid exercise data"})
		return
	}

	exercise := Exercise{
		Title:       input.Title,
		Sets:        input.Sets,
		Repetitions: input.Repetitions,
		WorkoutID:   uint(workoutID),
	}

	if err := db.Create(&exercise).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create exercise"})
		return
	}

	c.JSON(http.StatusCreated, exercise)
}


func connectDB() {
	dsn := "workout_user:Workout_Password$1234@tcp(localhost:3306)/workout_database?parseTime=true&loc=Local"
	dbConn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	db = dbConn
	db.AutoMigrate(&User{}, &Workout{}, &Exercise{})
	log.Println("✅ Database connected & migrated")

}



func UpdateExercise(c *gin.Context) {
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

	exerciseID := c.Param("exercise_id")
	var exercise Exercise
	if err := db.First(&exercise, exerciseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exercise not found"})
		return
	}

	var input struct {
		Title string  `json:"title"`
		Sets int `json:"sets"`
		Repetitions int `json:"repetitions"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid exercise data"})
		return
	}

	if input.Title != "" {
		exercise.Title = input.Title
	}
	if input.Sets > 0 {
		exercise.Sets = input.Sets
	}
	if input.Repetitions > 0 {
		exercise.Repetitions = input.Repetitions
	}

	if err := db.Save(&exercise).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update exercise"})
		return
	}

	c.JSON(http.StatusOK, exercise)
}

func GetAllExercises(c *gin.Context) {
	var exercises []Exercise

	result := db.Find(&exercises)
	if result.Error != nil {
		c.JSON(500, gin.H{"message": "Failed to fetch data"})
		return
	}

	c.JSON(200, exercises)
}

func DeleteExercise(c *gin.Context) {
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

	exerciseID := c.Param("exercise_id")
	var exercise Exercise
	if err := db.First(&exercise, exerciseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exercise not found"})
		return
	}

	if err := db.Delete(&exercise).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete Exercise"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Exercise deleted successfully"})
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

	r.POST("/workouts/:workout_id/exercises", AddExercise)
	r.PUT("/workouts/:workout_id/exercises/:exercise_id", UpdateExercise)
	r.GET("/workouts/:workout_id/exercises", GetAllExercises)
	r.DELETE("/workouts/:workout_id/exercises/:exercise_id", DeleteExercise)


	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}