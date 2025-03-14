package controller

import (
	"github.com/gin-gonic/gin"
	CompilerService "github.com/lijuuu/GlobalProtoXcode/Compiler"
)

type CompilerController struct {
	compilerClient CompilerService.CompilerServiceClient
}

func NewCompilerController(compilerClient CompilerService.CompilerServiceClient) *CompilerController {
	return &CompilerController{compilerClient: compilerClient}
}

type ExecutionRequest struct {
	Code     string `json:"code" binding:"required"`
	Language string `json:"language" binding:"required"`
}


type ExecutionResponse struct {
	Output        string `json:"output"`
	Error         string `json:"error,omitempty"`
	StatusMessage string `json:"status_message"`
	Success       bool   `json:"success"`
	ExecutionTime string `json:"execution_time,omitempty"`
}

func (s *CompilerController) CompileCodeHandler(c *gin.Context) {
	var req ExecutionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ExecutionResponse{
			Error:         err.Error(),
			StatusMessage: "API request failed",
			Success:       false,
		})
		return
	}

	resp, err := s.compilerClient.Compile(c.Request.Context(), &CompilerService.CompileRequest{
		Code:     req.Code,
		Language: req.Language,
	})

	if err != nil {
		c.JSON(500, ExecutionResponse{
			Error:         err.Error(),
			StatusMessage: "API request failed",
			Success:       false,
		})
	}

	c.JSON(200, ExecutionResponse{
		Output:        resp.Output,
		Error:         resp.Error,
		StatusMessage: resp.StatusMessage,
		Success:       resp.Success,
		ExecutionTime: resp.ExecutionTime,
	})
}
