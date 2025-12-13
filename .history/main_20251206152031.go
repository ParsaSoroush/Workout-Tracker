ackage main

import (
	"fmt"
	"log"
	"net/http"
	"os"
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