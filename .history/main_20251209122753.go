package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB
var JwtSecretKey = []byte("SECRET_KEY")


type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"unique;not null" json:"username"`
	Password  string    `gorm:"not null" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	Workouts  []Workout `json:"-"`
}

type Exercise struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"not null" json:"name"`
	Description string    `json:"description"`
	Category    string    `gorm:"not null" json:"category"`
	MuscleGroup string    `gorm:"not null" json:"muscle_group"`
	CreatedAt   time.Time `json:"created_at"`
}

type Workout struct {
	ID           uint              `gorm:"primaryKey" json:"id"`
	Title        string            `gorm:"not null" json:"title"`
	Description  string            `json:"description"`
	Comments     string            `json:"comments"`
	ScheduledFor time.Time         `gorm:"not null" json:"scheduled_for"`
	CreatedAt    time.Time         `json:"created_at"`
	UserID       uint              `gorm:"not null" json:"user_id"`
	Exercises    []WorkoutExercise `gorm:"constraint:OnDelete:CASCADE;" json:"exercises"`
}

type WorkoutExercise struct {
	ID          uint     `gorm:"primaryKey" json:"id"`
	WorkoutID   uint     `gorm:"index;not null" json:"workout_id"`
	ExerciseID  uint     `gorm:"index;not null" json:"exercise_id"`
	Sets        int      `json:"sets"`
	Repetitions int      `json:"repetitions"`
	Weight      float64  `json:"weight"`
	Exercise    Exercise `gorm:"foreignKey:ExerciseID" json:"exercise"`
	CreatedAt   time.Time `json:"created_at"`
}

func connectDB() {
	dsn := "workout_user:Workout_Password$1234@tcp(localhost:3306)/workout_database?parseTime=true&loc=Local"
	dbConn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	db = dbConn

	if err := db.AutoMigrate(&User{}, &Exercise{}, &Workout{}, &WorkoutExercise{}); err != nil {
		log.Fatal("❌ AutoMigrate failed:", err)
	}

	log.Println("✅ Database migrated")
}

func generateTokenForUser(u *User, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  u.ID,
		"username": u.Username,
		"exp":      time.Now().Add(expiry).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecretKey)
}

func parseTokenString(tokenString string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, errors.New("no token provided")
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	expVal, ok := claims["exp"]
	if !ok {
		return nil, errors.New("exp not present in token")
	}
	var exp int64
	switch v := expVal.(type) {
	case float64:
		exp = int64(v)
	case int64:
		exp = v
	default:
		return nil, errors.New("invalid exp type in token")
	}
	if time.Now().After(time.Unix(exp, 0)) {
		return nil, errors.New("token is expired")
	}
	return claims, nil
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		claims, err := parseTokenString(authHeader)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func getClaimsFromContext(c *gin.Context) (jwt.MapClaims, error) {
	val, ok := c.Get("claims")
	if !ok {
		return nil, errors.New("no claims in context")
	}
	claims, ok := val.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims in context")
	}
	return claims, nil
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

	hashedPw, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}
	user := User{Username: req.Username, Password: string(hashedPw)}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokenString, err := generateTokenForUser(&user, time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
		"token":   tokenString,
		"user": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"created_at": user.CreatedAt,
		},
	})
}

func SignIn(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	tokenString, err := generateTokenForUser(&user, time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   tokenString,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
		},
	})
}

func Logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful. Please delete token on client."})
}


func GetExerciseCatalog(c *gin.Context) {
	var exercises []Exercise
	if err := db.Order("name asc").Find(&exercises).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch exercises"})
		return
	}
	c.JSON(http.StatusOK, exercises)
}


func AddExercise(c *gin.Context) {
	var input struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Category    string `json:"category" binding:"required"`
		MuscleGroup string `json:"muscle_group" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid exercise data"})
		return
	}

	exercise := Exercise{
		Name:        input.Name,
		Description: input.Description,
		Category:    input.Category,
		MuscleGroup: input.MuscleGroup,
	}

	if err := db.Create(&exercise).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create exercise"})
		return
	}

	c.JSON(http.StatusCreated, exercise)
}


func UpdateExercise(c *gin.Context) {


	exerciseID := c.Param("exercise_id")

	var exercise Exercise
	if err := db.First(&exercise, exerciseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exercise not found"})
		return
	}

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Category    string `json:"category"`
		MuscleGroup string `json:"muscle_group"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid exercise data"})
		return
	}

	if input.Name != "" {
		exercise.Name = input.Name
	}
	if input.Description != "" {
		exercise.Description = input.Description
	}
	if input.Category != "" {
		exercise.Category = input.Category
	}
	if input.MuscleGroup != "" {
		exercise.MuscleGroup = input.MuscleGroup
	}

	if err := db.Save(&exercise).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update exercise"})
		return
	}

	c.JSON(http.StatusOK, exercise)
}

// GET ALL EXERCISES FOR A WORKOUT
func GetAllExercises(c *gin.Context) {
	// Validate token
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

	wid := c.Param("workout_id")

	// Ensure workout belongs to the user
	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", wid, userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Workout not found or access denied"})
		return
	}

	var exercises []Exercise
	if err := db.Where("workout_id = ?", workout.ID).Find(&exercises).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to fetch exercises"})
		return
	}

	c.JSON(http.StatusOK, exercises)
}

// DELETE EXERCISE
func DeleteExercise(c *gin.Context) {
	// Validate token
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

	// Check workout
	wid := c.Param("workout_id")
	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", wid, userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Workout not found or access denied"})
		return
	}

	eid := c.Param("exercise_id")

	var exercise Exercise
	if err := db.Where("id = ? AND workout_id = ?", eid, workout.ID).First(&exercise).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exercise not found"})
		return
	}

	if err := db.Delete(&exercise).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete exercise"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Exercise deleted successfully"})
}


func AddWorkout(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))

	var input struct {
		Title        string `json:"title" binding:"required"`
		Description  string `json:"description"`
		Comments     string `json:"comments"`
		ScheduledFor string `json:"scheduled_for" binding:"required"` // RFC3339
		Exercises    []struct {
			ExerciseID  uint    `json:"exercise_id" binding:"required"`
			Sets        int     `json:"sets"`
			Repetitions int     `json:"repetitions"`
			Weight      float64 `json:"weight"`
		} `json:"exercises"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid workout data: " + err.Error()})
		return
	}

	scheduledTime, err := time.Parse(time.RFC3339, input.ScheduledFor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid datetime format. Use RFC3339"})
		return
	}

	workout := Workout{
		Title:        input.Title,
		Description:  input.Description,
		Comments:     input.Comments,
		ScheduledFor: scheduledTime,
		UserID:       userID,
	}

	if err := db.Create(&workout).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create workout"})
		return
	}

	for _, e := range input.Exercises {
		var ex Exercise
		if err := db.First(&ex, e.ExerciseID).Error; err != nil {
			db.Delete(&workout)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("exercise id %d not found", e.ExerciseID)})
			return
		}
		we := WorkoutExercise{
			WorkoutID:   workout.ID,
			ExerciseID:  e.ExerciseID,
			Sets:        e.Sets,
			Repetitions: e.Repetitions,
			Weight:      e.Weight,
		}
		if err := db.Create(&we).Error; err != nil {
			db.Delete(&workout)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to attach exercises"})
			return
		}
	}

	if err := db.Preload("Exercises.Exercise").First(&workout, workout.ID).Error; err != nil {
		c.JSON(http.StatusCreated, gin.H{"workout_id": workout.ID})
		return
	}

	c.JSON(http.StatusCreated, workout)
}

func GetAllWorkouts(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))

	var workouts []Workout
	if err := db.Preload("Exercises.Exercise").
		Where("user_id = ? AND scheduled_for >= ?", userID, time.Now()).
		Order("scheduled_for ASC").
		Find(&workouts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workouts"})
		return
	}
	c.JSON(http.StatusOK, workouts)
}

func UpdateWorkout(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))
	workoutID := c.Param("workout_id")

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", workoutID, userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workout not found"})
		return
	}

	var input struct {
		Title        string `json:"title"`
		Description  string `json:"description"`
		Comments     string `json:"comments"`
		ScheduledFor string `json:"scheduled_for"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid workout data"})
		return
	}

	if input.Title != "" {
		workout.Title = input.Title
	}
	if input.Description != "" {
		workout.Description = input.Description
	}
	if input.Comments != "" {
		workout.Comments = input.Comments
	}
	if input.ScheduledFor != "" {
		t, err := time.Parse(time.RFC3339, input.ScheduledFor)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid datetime format"})
			return
		}
		workout.ScheduledFor = t
	}

	if err := db.Save(&workout).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update workout"})
		return
	}

	if err := db.Preload("Exercises.Exercise").First(&workout, workout.ID).Error; err != nil {
		c.JSON(http.StatusOK, workout)
		return
	}
	c.JSON(http.StatusOK, workout)
}

func DeleteWorkout(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))
	workoutID := c.Param("workout_id")

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", workoutID, userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Workout not found"})
		return
	}

	if err := db.Delete(&workout).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete workout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Workout deleted successfully"})
}


func AddExerciseToWorkout(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))
	workoutIDParam := c.Param("workout_id")
	workoutID, err := strconv.ParseUint(workoutIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workout id"})
		return
	}

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", uint(workoutID), userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "workout not found or access denied"})
		return
	}

	var input struct {
		ExerciseID  uint    `json:"exercise_id" binding:"required"`
		Sets        int     `json:"sets"`
		Repetitions int     `json:"repetitions"`
		Weight      float64 `json:"weight"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exercise data"})
		return
	}

	var ex Exercise
	if err := db.First(&ex, input.ExerciseID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exercise not found"})
		return
	}

	we := WorkoutExercise{
		WorkoutID:   uint(workoutID),
		ExerciseID:  input.ExerciseID,
		Sets:        input.Sets,
		Repetitions: input.Repetitions,
		Weight:      input.Weight,
	}
	if err := db.Create(&we).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add exercise to workout"})
		return
	}

	if err := db.Preload("Exercise").First(&we, we.ID).Error; err != nil {
		c.JSON(http.StatusCreated, we)
		return
	}
	c.JSON(http.StatusCreated, we)
}

func UpdateWorkoutExercise(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))
	workoutIDParam := c.Param("workout_id")
	workoutID, err := strconv.ParseUint(workoutIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workout id"})
		return
	}
	exerciseRelID := c.Param("exercise_id")

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", uint(workoutID), userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "workout not found or access denied"})
		return
	}

	var we WorkoutExercise
	if err := db.Where("id = ? AND workout_id = ?", exerciseRelID, uint(workoutID)).First(&we).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "exercise entry not found in workout"})
		return
	}

	var input struct {
		Sets        *int     `json:"sets"`
		Repetitions *int     `json:"repetitions"`
		Weight      *float64 `json:"weight"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data"})
		return
	}

	if input.Sets != nil {
		we.Sets = *input.Sets
	}
	if input.Repetitions != nil {
		we.Repetitions = *input.Repetitions
	}
	if input.Weight != nil {
		we.Weight = *input.Weight
	}

	if err := db.Save(&we).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update exercise entry"})
		return
	}

	if err := db.Preload("Exercise").First(&we, we.ID).Error; err != nil {
		c.JSON(http.StatusOK, we)
		return
	}
	c.JSON(http.StatusOK, we)
}

func GetExercisesForWorkout(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))
	workoutIDParam := c.Param("workout_id")
	workoutID, err := strconv.ParseUint(workoutIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workout id"})
		return
	}

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", uint(workoutID), userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "workout not found or access denied"})
		return
	}

	var items []WorkoutExercise
	if err := db.Preload("Exercise").Where("workout_id = ?", uint(workoutID)).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch exercises"})
		return
	}
	c.JSON(http.StatusOK, items)
}

func DeleteExerciseFromWorkout(c *gin.Context) {
	claims, err := getClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := uint(claims["user_id"].(float64))
	workoutIDParam := c.Param("workout_id")
	workoutID, err := strconv.ParseUint(workoutIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workout id"})
		return
	}
	exerciseRelID := c.Param("exercise_id") // WorkoutExercise.ID

	var workout Workout
	if err := db.Where("id = ? AND user_id = ?", uint(workoutID), userID).First(&workout).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "workout not found or access denied"})
		return
	}

	var we WorkoutExercise
	if err := db.Where("id = ? AND workout_id = ?", exerciseRelID, uint(workoutID)).First(&we).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "exercise entry not found in workout"})
		return
	}

	if err := db.Delete(&we).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete exercise from workout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "exercise removed from workout"})
}


func CheckToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	claims, err := parseTokenString(authHeader)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	expFloat := int64(claims["exp"].(float64))
	expTime := time.Unix(expFloat, 0)
	remaining := time.Until(expTime)
	c.JSON(http.StatusOK, gin.H{
		"message":   "Token is valid",
		"remaining": remaining.String(),
		"user": gin.H{
			"id":       claims["user_id"],
			"username": claims["username"],
		},
	})
}


func main() {
	connectDB()

	r := gin.Default()

	r.POST("/sign-up", SignUp)
	r.POST("/sign-in", SignIn)
	r.POST("/logout", Logout)
	r.POST("/check", CheckToken)
	r.GET("/exercises/catalog", GetExerciseCatalog)
	auth := r.Group("/")
	auth.Use(AuthRequired())
	auth.POST("/workouts", AddWorkout)
	auth.GET("/workouts", GetAllWorkouts)
	auth.PUT("/workouts/:workout_id", UpdateWorkout)
	auth.DELETE("/workouts/:workout_id", DeleteWorkout)
	auth.POST("/workouts/:workout_id/exercises", AddExerciseToWorkout)
	auth.PUT("/workouts/:workout_id/exercises/:exercise_id", UpdateWorkoutExercise)
	auth.GET("/workouts/:workout_id/exercises", GetExercisesForWorkout)
	auth.DELETE("/workouts/:workout_id/exercises/:exercise_id", DeleteExerciseFromWorkout)
	auth.POST("/exercises", AddExercise)
	auth.PUT("/exercises/:exercise_id")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("🚀 Server running on :%s\n", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("server failed:", err)
	}
}
