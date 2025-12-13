package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB
var JwtSecretKey = []byte("SECRET_KEY")

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
	IsAdmin  bool   `gorm:"default:false"`
	Carts    []Cart
}

type Product struct {
	ID    uint    `gorm:"primaryKey"`
	Title string  `gorm:"not null"`
	Price float64 `gorm:"not null"`
	Stock int     `gorm:"default:0"`
}

type Cart struct {
	ID         uint `gorm:"primaryKey"`
	UserID     uint `gorm:"index"`
	Items      []CartItem
	CheckedOut bool `gorm:"default:false"`
	CreatedAt  time.Time
}

type CartItem struct {
	ID        uint `gorm:"primaryKey"`
	CartID    uint
	ProductID uint
	Product   Product
	Quantity  int `gorm:"default:1"`
	UnitPrice float64
}

type Payment struct {
	ID         uint `gorm:"primaryKey"`
	CartID     uint
	Amount     float64
	Provider   string
	ProviderID string
	CreatedAt  time.Time
}

func connectDB() {
	dsn := "e_commerce:E-Commerce$1234@tcp(localhost:3306)/e_commerce?charset=utf8mb4&parseTime=True&loc=Local"
	dbConn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	db = dbConn
	db.AutoMigrate(&User{}, &Product{}, &Cart{}, &CartItem{}, &Payment{}, &Card{})
	log.Println("✅ Database connected & migrated")

	// Seed a couple of demo cards if none exist
}

func main() {
	connectDB()

	r := gin.Default()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}