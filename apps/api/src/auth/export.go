package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

func New(v1 fiber.Router) {
	route := v1.Group("/auth")

	route.Post("/login", Login)
	route.Post("/reset", ResetPassword)
}

func RegisterUserRepository(c *fiber.Ctx, db *sqlx.DB) {
	Repo := &AuthSqlxRepo{db: db}
	c.Locals("AuthRepo", Repo)
}
