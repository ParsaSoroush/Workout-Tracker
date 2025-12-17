package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var testDB *gorm.DB

func setupTestDB() (*gorm.DB, error) {
	dsn := "workout_user:Workout_Password$1234@tcp(localhost:3306)/workout_database?parseTime=true&loc=Local"
	dbConn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Reset tables
	_ = dbConn.Migrator().DropTable(&User{}, &Exercise{}, &Workout{}, &WorkoutExercise{})
	if err := dbConn.AutoMigrate(&User{}, &Exercise{}, &Workout{}, &WorkoutExercise{}); err != nil {
		return nil, err
	}

	return dbConn, nil
}

func TestMain(m *testing.M) {
	var err error
	testDB, err = setupTestDB()
	if err != nil {
		panic("failed to connect to test database: " + err.Error())
	}

	db = testDB // assign global db used in main.go
	m.Run()
}

func TestUserAuth(t *testing.T) {
	// Create user
	pw := "password123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	user := User{Username: "simpleuser", Password: string(hashed)}
	if err := testDB.Create(&user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Login success
	var u User
	if err := testDB.Where("username = ?", "simpleuser").First(&u).Error; err != nil {
		t.Fatalf("User not found: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pw)); err != nil {
		t.Errorf("Password mismatch: %v", err)
	}

	// Generate token
	token, err := generateTokenForUser(&u, time.Hour)
	if err != nil || token == "" {
		t.Errorf("Failed to generate token")
	}
}

func TestWorkoutAndExercise(t *testing.T) {
	pw := "password123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	user := User{Username: "workoutuser", Password: string(hashed)}
	if err := testDB.Create(&user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	ex := Exercise{Name: "Push Up", Category: "Strength", MuscleGroup: "Chest"}
	if err := testDB.Create(&ex).Error; err != nil {
		t.Fatalf("Failed to create exercise: %v", err)
	}

	workout := Workout{
		Title:        "Morning",
		Status:       "pending",
		ScheduledFor: time.Now(),
		UserID:       user.ID,
	}
	if err := testDB.Create(&workout).Error; err != nil {
		t.Fatalf("Failed to create workout: %v", err)
	}

	we := WorkoutExercise{
		WorkoutID:   workout.ID,
		ExerciseID:  ex.ID,
		Sets:        3,
		Repetitions: 15,
		Weight:      0,
	}
	if err := testDB.Create(&we).Error; err != nil {
		t.Fatalf("Failed to add exercise to workout: %v", err)
	}

	var fetched Workout
	if err := testDB.Preload("Exercises.Exercise").First(&fetched, workout.ID).Error; err != nil {
		t.Errorf("Failed to fetch workout: %v", err)
	}
	if len(fetched.Exercises) != 1 || fetched.Exercises[0].Exercise.Name != "Push Up" {
		t.Errorf("Workout exercises not linked correctly")
	}
}
