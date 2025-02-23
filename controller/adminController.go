package controller

import (
	"net/http"
	model "xcode/model"

	"github.com/gin-gonic/gin"
)

type AdminController struct{}

func NewAdminController() *AdminController {
	return &AdminController{}
}

func (c *AdminController) LoginAdminHandler(ctx *gin.Context) {
	var req model.LoginAdminRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
		})
	}
}
