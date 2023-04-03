package auth

import (
	"api/src/common"
	"api/src/user"
	"api/src/utils"
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	Login(email string) (*user.User, error)
	ResetPass(email string) (*user.User, error)
	ChangePass(userId uint, newPass string) (*user.User, error)
}

type AuthSqlxRepo struct {
	db *sqlx.DB
}

// Login godoc
// @Summary Login api
// @Description Login api
// @Accept json
// @Produce json
// @Param project body LoginBody true "Login payload"
// @Success 200 {object} LoginResp
// @Failure 404 {string} string
// @Failure 500 {string} string
// @Router /auth/login [post]
// @tags Auth
func Login(ctx *fiber.Ctx) error {
	req := LoginBody{}
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(err)
	}

	if err := common.ValidatorAdapter.Exec(req); err != nil {
		return ctx.Status(http.StatusUnprocessableEntity).JSON(err)
	}

	repo := ctx.Locals("AuthRepo").(AuthRepository)
	user, err := repo.Login(req.Email)
	if err != nil {
		var httpErr common.HttpError
		if errors.As(err, &httpErr) {
			return ctx.Status(httpErr.Code).JSON(httpErr.Message)
		}

		return ctx.JSON(err.Error())
	}

	res, err := utils.VerifyPassword(req.Password, user.Password)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON("Internal error")
	}

	if !res {
		return ctx.Status(http.StatusConflict).JSON("Wrong password")
	}

	AcccessToken, RefreshToken := utils.GenerateToken(user.Id, []byte("jwtsec"), []byte("refreshSec"))

	token := LoginResp{
		AccessToken:  AcccessToken,
		RefreshToken: RefreshToken,
	}

	return ctx.JSON(token)
}

// Reset godoc
// @Summary Reset api
// @Description Reset api
// @Accept json
// @Produce json
// @Param user body ResetPassBody true "Reset password payload"
// @Success 200 {object} LoginResp
// @Failure 404 {string} string
// @Failure 500 {string} string
// @Router /auth/reset [post]
// @tags Auth
func ResetPassword(ctx *fiber.Ctx) error {
	checkEmail := ResetPassBody{}
	if err := ctx.BodyParser(&checkEmail); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(err)
	}

	if err := common.ValidatorAdapter.Exec(&checkEmail); err != nil {
		return ctx.Status(http.StatusUnprocessableEntity).JSON(err)
	}
	repo := ctx.Locals("AuthRepo").(AuthRepository)
	checkUser, err := repo.ResetPass(checkEmail.Email)
	if err != nil {
		var httpErr common.HttpError
		if errors.As(err, &httpErr) {
			return ctx.Status(httpErr.Code).JSON(httpErr.Message)
		}
		return ctx.JSON(err.Error())
	}
	AccessToken := utils.GenerateAccessToken(checkUser.Id, []byte("jwtec"))
	token := ResetPassResp{
		AccessToken: AccessToken,
	}
	return ctx.JSON(token)
}

func ChangePassword(ctx *fiber.Ctx) error {
	newPass := NewPassBody{}
	token := ResetPassResp{}
	if err := ctx.BodyParser(&newPass); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(err)
	}

	if err := common.ValidatorAdapter.Exec(&newPass); err != nil {
		return ctx.Status(http.StatusUnprocessableEntity).JSON(err)
	}
	repo := ctx.Locals("AuthRepo").(AuthRepository)
	userId, err := utils.ParseToken(token.AccessToken, []byte("jwtec"))
	if err != nil {
		return ctx.JSON(err)
	}
	changePass, errP := repo.ChangePass(userId, newPass.Password)
	if errP != nil {
		var httpErr common.HttpError
		if errors.As(errP, &httpErr) {
			return ctx.Status(httpErr.Code).JSON(httpErr.Message)
		}
		return ctx.JSON(errP.Error())
	}
	return ctx.JSON(changePass)
}
