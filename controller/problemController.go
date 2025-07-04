package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
	"xcode/customerrors"
	"xcode/model"

	"github.com/gin-gonic/gin"
	authUserAdminPB "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	problemPB "github.com/lijuuu/GlobalProtoXcode/ProblemsService"
	"google.golang.org/grpc/status"
)

type ProblemController struct {
	problemClient problemPB.ProblemsServiceClient
	userClient    authUserAdminPB.AuthUserAdminServiceClient
}

func NewProblemController(problemClient problemPB.ProblemsServiceClient, userClient authUserAdminPB.AuthUserAdminServiceClient) *ProblemController {
	return &ProblemController{problemClient: problemClient, userClient: userClient}
}

func (c *ProblemController) CreateProblemHandler(ctx *gin.Context) {
	var req problemPB.CreateProblemRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}

	resp, err := c.problemClient.CreateProblem(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to create problem", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"problem_id": resp.ProblemId, "message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) UpdateProblemHandler(ctx *gin.Context) {
	var req problemPB.UpdateProblemRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}
	resp, err := c.problemClient.UpdateProblem(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to update problem", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) DeleteProblemHandler(ctx *gin.Context) {
	problemID := ctx.Query("problem_id")
	if problemID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_PARAM_EMPTY, Code: http.StatusBadRequest, Message: "Missing problem_id", Details: "problem_id is required"},
		})
		return
	}
	resp, err := c.problemClient.DeleteProblem(ctx.Request.Context(), &problemPB.DeleteProblemRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to delete problem", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) GetProblemHandler(ctx *gin.Context) {
	problemID := ctx.Query("problem_id")
	if problemID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_PARAM_EMPTY, Code: http.StatusBadRequest, Message: "Missing problem_id", Details: "problem_id is required"},
		})
		return
	}
	resp, err := c.problemClient.GetProblem(ctx.Request.Context(), &problemPB.GetProblemRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to get problem", Details: grpcStatus.Message()},
		})
		return
	}
	if resp.Problem == nil {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "NOT_FOUND", Code: http.StatusNotFound, Message: "Problem not found", Details: "Problem not found"},
		})
		return
	}
	fmt.Println("visible ", resp.Problem.Visible)
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Problem,
		Error:   nil,
	})
}

func (c *ProblemController) ListProblemsHandler(ctx *gin.Context) {
	var req problemPB.ListProblemsRequest
	if page, err := strconv.Atoi(ctx.Query("page")); err == nil && page > 0 {
		req.Page = int32(page)
	}
	if pageSize, err := strconv.Atoi(ctx.Query("page_size")); err == nil && pageSize > 0 {
		req.PageSize = int32(pageSize)
	}
	req.Tags = ctx.QueryArray("tags")
	req.Difficulty = ctx.Query("difficulty")
	req.SearchQuery = ctx.Query("search_query")
	req.TraceID = GetTraceID(&ctx.Request.Header)

	// if role, ok := ctx.Get(middleware.RoleKey); ok && role == middleware.RoleAdmin {
	// 	req.IsAdmin = true
	// } else {
	// 	req.IsAdmin = false
	// }

	resp, err := c.problemClient.ListProblems(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to list problems", Details: grpcStatus.Message()},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"problems":    resp.Problems,
			"total_count": resp.TotalCount,
			"page":        resp.Page,
			"page_size":   resp.PageSize,
		},
		Error: nil,
	})
}

func (c *ProblemController) AddTestCasesHandler(ctx *gin.Context) {
	var req problemPB.AddTestCasesRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}
	resp, err := c.problemClient.AddTestCases(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to add test cases", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message, "added_count": resp.AddedCount},
		Error:   nil,
	})
}

func (c *ProblemController) DeleteTestCaseHandler(ctx *gin.Context) {
	var req problemPB.DeleteTestCaseRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}
	if req.ProblemId == "" || req.TestcaseId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_PARAM_EMPTY, Code: http.StatusBadRequest, Message: "Missing required parameters", Details: "problem_id and testcase_id are required"},
		})
		return
	}
	resp, err := c.problemClient.DeleteTestCase(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to delete test case", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) AddLanguageSupportHandler(ctx *gin.Context) {
	var req problemPB.AddLanguageSupportRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}
	resp, err := c.problemClient.AddLanguageSupport(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to add language support", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) UpdateLanguageSupportHandler(ctx *gin.Context) {
	var req problemPB.UpdateLanguageSupportRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}
	resp, err := c.problemClient.UpdateLanguageSupport(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to update language support", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) RemoveLanguageSupportHandler(ctx *gin.Context) {
	var req problemPB.RemoveLanguageSupportRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}
	resp, err := c.problemClient.RemoveLanguageSupport(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to remove language support", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) FullValidationByProblemIDHandler(ctx *gin.Context) {
	problemID := ctx.Query("problem_id")
	if problemID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_PARAM_EMPTY, Code: http.StatusBadRequest, Message: "Missing problem_id", Details: "problem_id is required"},
		})
		return
	}

	resp, err := c.problemClient.FullValidationByProblemID(ctx.Request.Context(), &problemPB.FullValidationByProblemIDRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
	fmt.Println("API Controller Response:", resp, err) // Debug log

	// Check if the response is nil
	// if resp == nil {
	// 	ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
	// 		Success: false,
	// 		Status:  http.StatusInternalServerError,
	// 		Payload: nil,
	// 		Error:   &model.ErrorInfo{ErrorType: "VALIDATION_FAILED", Code: http.StatusInternalServerError, Message: "Validation failed, response is nil", Details: "The gRPC response is nil"},
	// 	})
	// 	return
	// }

	// Handle gRPC error
	if err != nil {
		grpcStatus, ok := status.FromError(err)
		if !ok {
			ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
				Success: false,
				Status:  http.StatusInternalServerError,
				Payload: nil,
				Error:   &model.ErrorInfo{ErrorType: "INTERNAL_ERROR", Code: http.StatusInternalServerError, Message: "Internal server error", Details: err.Error()},
			})
			return
		}
		// Use grpcStatus details if available, fallback to generic error
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "VALIDATION_ERROR", Code: http.StatusBadRequest, Message: grpcStatus.Message(), Details: grpcStatus.Message()},
		})
		return
	}

	// Handle unsuccessful response
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}

	// Successful response
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{"message": resp.Message},
		Error:   nil,
	})
}

func (c *ProblemController) GetLanguageSupportsHandler(ctx *gin.Context) {
	problemID := ctx.Query("problem_id")
	if problemID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_PARAM_EMPTY, Code: http.StatusBadRequest, Message: "Missing problem_id", Details: "problem_id is required"},
		})
		return
	}
	resp, err := c.problemClient.GetLanguageSupports(ctx.Request.Context(), &problemPB.GetLanguageSupportsRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to get language supports", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"supported_languages": resp.SupportedLanguages,
			"validate_code":       resp.ValidateCode,
			"message":             resp.Message,
		},
		Error: nil,
	})
}

func (c *ProblemController) GetProblemByIDSlugHandler(ctx *gin.Context) {
	problemID := ctx.Query("problem_id")
	slug := ctx.Query("slug")
	if problemID == "" && slug == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_PARAM_EMPTY, Code: http.StatusBadRequest, Message: "Missing problem_id or slug", Details: "problem_id or slug is required"},
		})
		return
	}
	req := &problemPB.GetProblemByIdSlugRequest{
		ProblemId: problemID,
		TraceID:   GetTraceID(&ctx.Request.Header),
	}
	if slug != "" {
		req.Slug = &slug
	}
	resp, err := c.problemClient.GetProblemByIDSlug(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to get problem metadata", Details: grpcStatus.Message()},
		})
		return
	}
	if resp.Problemmetdata == nil {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "NOT_FOUND", Code: http.StatusNotFound, Message: "Problem not found", Details: resp.Message},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Problemmetdata,
		Error:   nil,
	})
}

func (c *ProblemController) GetProblemMetadataListHandler(ctx *gin.Context) {
	var req problemPB.GetProblemMetadataListRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if page, err := strconv.Atoi(ctx.Query("page")); err == nil && page > 0 {
		req.Page = int32(page)
	}
	if pageSize, err := strconv.Atoi(ctx.Query("page_size")); err == nil && pageSize > 0 {
		req.PageSize = int32(pageSize)
	}
	req.Tags = ctx.QueryArray("tags")
	req.Difficulty = ctx.Query("difficulty")
	req.SearchQuery = ctx.Query("search_query")
	resp, err := c.problemClient.GetProblemMetadataList(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to list problem metadata", Details: grpcStatus.Message()},
		})
		return
	}
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"problems":    resp.Problemmetdata,
			"total_count": len(resp.Problemmetdata),
			"page":        req.Page,
			"page_size":   req.PageSize,
		},
		Error: nil,
	})
}

func (c *ProblemController) RunUserCodeProblemHandler(ctx *gin.Context) {
	var req problemPB.RunProblemRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		// fmt.Println("bind json failed ", req)

		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: map[string]interface{}{
				"problem_id":      req.ProblemId,
				"language":        req.Language,
				"is_run_testcase": req.IsRunTestcase,
				"rawoutput": model.UniversalExecutionResult{
					TotalTestCases:  0,
					PassedTestCases: 0,
					FailedTestCases: 0,
					FailedTestCase: model.TestCaseResult{
						TestCaseIndex: -1,
						Error:         fmt.Sprintf("Invalid request payload: %v", err),
					},
					OverallPass: false,
					SyntaxError: "",
				},
			},
			Error: nil,
		})
		return
	}

	// userID, exists := ctx.Get(middleware.EntityIDKey)
	// if !exists || userID == nil {
	// 	fmt.Println("no userID")
	// } else {
	// 	req.UserId = userID.(string)
	// }

	// Validate required fields
	if req.ProblemId == "" || req.UserCode == "" || req.Language == "" || req.UserId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: map[string]interface{}{
				"problem_id":      req.ProblemId,
				"language":        req.Language,
				"is_run_testcase": req.IsRunTestcase,
				"rawoutput": model.UniversalExecutionResult{
					TotalTestCases:  0,
					PassedTestCases: 0,
					FailedTestCases: 0,
					FailedTestCase: model.TestCaseResult{
						TestCaseIndex: -1,
						Error:         "Missing required fields: problem_id, user_code, and language are required",
					},
					OverallPass: false,
					SyntaxError: "",
				},
			},
			Error: nil,
		})
		return
	}

	getUserProfileRequest := &authUserAdminPB.GetUserProfileRequest{
		UserID: req.UserId,
	}

	resp, err := c.userClient.GetUserProfile(context.Background(), getUserProfileRequest)
	if err != nil {

		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_CRED_CHECK_FAILED,
				Code:      http.StatusBadRequest,
				Message:   "run user's problem failed",
				Details:   "run user's problem failed",
			},
		})
		return
	}

	req.Country = &resp.UserProfile.Country

	// Call the gRPC service
	resp2, err := c.problemClient.RunUserCodeProblem(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: map[string]interface{}{
				"problem_id":      req.ProblemId,
				"language":        req.Language,
				"is_run_testcase": req.IsRunTestcase,
				"rawoutput": model.UniversalExecutionResult{
					TotalTestCases:  0,
					PassedTestCases: 0,
					FailedTestCases: 0,
					FailedTestCase: model.TestCaseResult{
						TestCaseIndex: -1,
						Error:         fmt.Sprintf("gRPC service error: %s", grpcStatus.Message()),
					},
					OverallPass: false,
					SyntaxError: "",
				},
			},
			Error: &model.ErrorInfo{
				ErrorType: "EXECUTION_FAILED",
				Message:   err.Error(),
			},
		})
		return
	}

	// Handle service response
	if !resp2.Success {
		httpCode := http.StatusBadRequest
		switch resp.ErrorType {
		case "NOT_FOUND":
			httpCode = http.StatusNotFound
		case "COMPILATION_ERROR":
			httpCode = http.StatusBadRequest
		case "EXECUTION_ERROR":
			httpCode = http.StatusBadRequest
		default:
			httpCode = http.StatusBadRequest
		}

		overallPass := false
		if resp.ErrorType == "" {
			overallPass = true
		}
		syntaxError := ""
		if resp.ErrorType == "COMPILATION_ERROR" {
			syntaxError = resp.Message
		}

		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: map[string]interface{}{
				"problem_id":      resp2.ProblemId,
				"language":        resp2.Language,
				"is_run_testcase": resp2.IsRunTestcase,
				"rawoutput": model.UniversalExecutionResult{
					TotalTestCases:  0,
					PassedTestCases: 0,
					FailedTestCases: 0,
					FailedTestCase: model.TestCaseResult{
						TestCaseIndex: -1,
						Error:         resp2.Message,
					},
					OverallPass: overallPass,
					SyntaxError: syntaxError,
				},
			},
			Error: nil,
		})
		return
	}

	// Parse the successful execution result
	var output model.UniversalExecutionResult
	if err := json.Unmarshal([]byte(resp2.Message), &output); err != nil {
		fmt.Println(err, output)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: map[string]interface{}{
				"problem_id":      resp2.ProblemId,
				"language":        resp2.Language,
				"is_run_testcase": resp2.IsRunTestcase,
				"rawoutput": model.UniversalExecutionResult{
					TotalTestCases:  0,
					PassedTestCases: 0,
					FailedTestCases: 0,
					FailedTestCase: model.TestCaseResult{
						TestCaseIndex: -1,
						Error:         fmt.Sprintf("Failed to parse execution result: %v", err),
					},
					OverallPass: false,
					SyntaxError: resp.Message,
				},
			},
			Error: &model.ErrorInfo{
				ErrorType: "UNMARSHAL_FAILED",
				Message:   fmt.Sprintf("Failed to parse execution result: %v", err),
			},
		})
		return
	}

	// Ensure OverallPass is set correctly based on test case results
	// if output.FailedTestCases == 0 && output.PassedTestCases == output.TotalTestCases {
	// 	output.OverallPass = true
	// } else {
	// 	output.OverallPass = false
	// }

	// Log for debugging
	fmt.Println("resp from execution:", resp)
	fmt.Println("parsed output:", output)

	// Success response
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"problem_id":      resp2.ProblemId,
			"language":        resp2.Language,
			"is_run_testcase": resp2.IsRunTestcase,
			"rawoutput":       output,
		},
		Error: nil,
	})
}

// {
// 	"success": false,
// 	"status": 500,
// 	"error": {
// 			"type": "GRPC_ERROR",
// 			"code": 500,
// 			"message": "Failed to run code",
// 			"details": "ErrorType: VALIDATION_ERROR, Code: 3, Details: Problem ID, user code, and language are required"
// 	}
// }

func (c *ProblemController) GetSubmissionHistoryOptionalProblemId(ctx *gin.Context) {
	userID := ctx.Query("userID")
	problemID := ctx.Query("problemID")
	pageStr := ctx.Query("page")
	limitStr := ctx.Query("limit")

	if userID == "" { //if userid is not present dont run the code
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required field: userID",
				Details:   "The userID query parameter is required",
			},
		})
		return
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1 //default
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10 //default
	}

	//prepare the gRPC request
	grpcReq := problemPB.GetSubmissionsRequest{
		UserId:    userID,
		ProblemId: &problemID,
		Page:      int32(page),
		Limit:     int32(limit),
		TraceID:   GetTraceID(&ctx.Request.Header),
	}

	resp, err := c.problemClient.GetSubmissionsByOptionalProblemID(ctx.Request.Context(), &grpcReq)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to create problem", Details: grpcStatus.Message()},
		})
		return
	}
	if !resp.Success {
		httpCode := http.StatusBadRequest
		if resp.ErrorType == "NOT_FOUND" {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: resp.ErrorType, Code: httpCode, Message: resp.Message, Details: resp.Message},
		})
		return
	}

	submissions := mapSubmissions(resp.Submissions)

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.SubmissionHistoryResponse{
			Submissions: submissions,
		},
		Error: nil,
	})

}

func mapSubmissions(pbSubmissions []*problemPB.Submission) []model.Submission {
	submissions := make([]model.Submission, len(pbSubmissions))
	for i, pbSubmission := range pbSubmissions {
		submissions[i] = model.Submission{
			ID:            pbSubmission.Id,
			UserID:        pbSubmission.UserId,
			ChallengeID:   pbSubmission.ChallengeId,
			ProblemID:     pbSubmission.ProblemId,
			Title:         pbSubmission.Title,
			Status:        pbSubmission.Status,
			Language:      pbSubmission.Language,
			Output:        pbSubmission.Output,
			UserCode:      pbSubmission.UserCode,
			SubmittedAt:   convertTimestampToTime(pbSubmission.SubmittedAt),
			ExecutionTime: float64(pbSubmission.ExecutionTime),
			Difficulty:    pbSubmission.Difficulty,
			IsFirst:       pbSubmission.IsFirst,
			Score:         int(pbSubmission.Score),
		}
	}
	return submissions
}

func convertTimestampToTime(pbTimestamp *problemPB.Timestamp) time.Time {
	// problemPB.RunProblemRequest
	if pbTimestamp == nil {
		return time.Time{}
	}
	return time.Unix(pbTimestamp.Seconds, int64(pbTimestamp.Nanos))
}

func (c *ProblemController) GetProblemStatistics(ctx *gin.Context) {
	// Extract userID from query parameters
	userID := ctx.Query("userID")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required field: userID",
				Details:   "The userID query parameter is required",
			},
		})
		return
	}

	// Prepare the gRPC request
	grpcReq := &problemPB.GetProblemsDoneStatisticsRequest{
		UserId:  userID,
		TraceID: GetTraceID(&ctx.Request.Header),
	}

	// Call the gRPC service
	resp, err := c.problemClient.GetProblemsDoneStatistics(ctx.Request.Context(), grpcReq)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "GRPC_ERROR",
				Code:      http.StatusInternalServerError,
				Message:   "Failed to fetch problem statistics",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	// Check if the response data is nil
	if resp.Data == nil {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "Problem statistics not found",
				Details:   "No statistics available for the given userID",
			},
		})
		return
	}

	// Map the gRPC response to the ProblemsDoneStatistics struct
	statistics := model.ProblemsDoneStatistics{
		MaxEasyCount:    resp.Data.MaxEasyCount,
		DoneEasyCount:   resp.Data.DoneEasyCount,
		MaxMediumCount:  resp.Data.MaxMediumCount,
		DoneMediumCount: resp.Data.DoneMediumCount,
		MaxHardCount:    resp.Data.MaxHardCount,
		DoneHardCount:   resp.Data.DoneHardCount,
	}

	// Return the successful response
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: statistics,
		Error:   nil,
	})
}

func (c *ProblemController) GetMonthlyActivityHeatmapController(ctx *gin.Context) {
	userID := ctx.Query("userID")
	monthStr := ctx.Query("month")
	yearStr := ctx.Query("year")

	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	month, err := strconv.Atoi(monthStr)
	if err != nil || month < 1 || month > 12 {
		// Set default values for month and year
		month = defaultMonth(month)
	}

	year, err := strconv.Atoi(yearStr)
	if err != nil || year < 1970 || year > 9999 {
		year = defaultYear(year)

	}

	grpcReq := &problemPB.GetMonthlyActivityHeatmapRequest{
		UserID:  userID,
		Month:   int32(month),
		Year:    int32(year),
		TraceID: GetTraceID(&ctx.Request.Header),
	}

	resp, err := c.problemClient.GetMonthlyActivityHeatmap(ctx.Request.Context(), grpcReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "GRPC_ERROR",
				Code:      http.StatusInternalServerError,
				Message:   "Failed to fetch monthly activity heatmap",
				Details:   err.Error(),
			},
		})
		return
	}

	if resp.Data == nil {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "Monthly activity heatmap not found",
				Details:   "No data available for the given userID, month, and year",
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Data,
		Error:   nil,
	})
}

// Helper functions to set default values
func defaultMonth(month int) int {
	if month == 0 {
		return int(time.Now().Month())
	}
	return month
}

func defaultYear(year int) int {
	if year == 0 {
		return time.Now().Year()
	}
	return year
}

func (c *ProblemController) GetTopKGlobalController(ctx *gin.Context) {
	kStr := ctx.Query("k")
	k, err := strconv.Atoi(kStr)
	if err != nil || k <= 0 {
		k = 10
	}

	grpcReq := &problemPB.GetTopKGlobalRequest{
		K:       int32(k),
		TraceID: GetTraceID(&ctx.Request.Header),
	}

	resp, err := c.problemClient.GetTopKGlobal(ctx.Request.Context(), grpcReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "GRPC_ERROR",
				Code:      http.StatusInternalServerError,
				Message:   "Failed to fetch top K global leaderboard",
				Details:   err.Error(),
			},
		})
		return
	}
	// fmt.Println("1",resp)

	if len(resp.Users) == 0 {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "No users found in global leaderboard",
				Details:   "No data available for the requested top K",
			},
		})
		return
	}
	// fmt.Println("1",resp)

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Users,
		Error:   nil,
	})
}

func (c *ProblemController) GetTopKEntityController(ctx *gin.Context) {
	entity := ctx.Query("entity")
	kStr := ctx.Query("k")
	if entity == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required query parameter",
				Details:   "entity is required",
			},
		})
		return
	}

	k, err := strconv.Atoi(kStr)
	if err != nil || k <= 0 {
		k = 10
	}

	grpcReq := &problemPB.GetTopKEntityRequest{
		Entity:  entity,
		TraceID: GetTraceID(&ctx.Request.Header),

		// K:      int32(k),
	}

	resp, err := c.problemClient.GetTopKEntity(ctx.Request.Context(), grpcReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "GRPC_ERROR",
				Code:      http.StatusInternalServerError,
				Message:   "Failed to fetch top K entity leaderboard",
				Details:   err.Error(),
			},
		})
		return
	}

	// fmt.Println(resp)

	if len(resp.Users) == 0 {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "No users found for the specified entity",
				Details:   fmt.Sprintf("No data available for entity %s", entity),
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Users,
		Error:   nil,
	})
}

func (c *ProblemController) GetUserRankController(ctx *gin.Context) {
	userID := ctx.Query("userID")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	grpcReq := &problemPB.GetUserRankRequest{
		UserId:  userID,
		TraceID: GetTraceID(&ctx.Request.Header),
	}

	resp, err := c.problemClient.GetUserRank(ctx.Request.Context(), grpcReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "GRPC_ERROR",
				Code:      http.StatusInternalServerError,
				Message:   "Failed to fetch user rank",
				Details:   err.Error(),
			},
		})
		return
	}

	if resp.GlobalRank == 0 && resp.EntityRank == 0 {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "User rank not found",
				Details:   fmt.Sprintf("No ranking data available for userID %s", userID),
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error:   nil,
	})
}

func (c *ProblemController) GetLeaderboardDataController(ctx *gin.Context) {
	userID := ctx.Query("userID")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	grpcReq := &problemPB.GetLeaderboardDataRequest{
		UserId:  userID,
		TraceID: GetTraceID(&ctx.Request.Header),
	}

	resp, err := c.problemClient.GetLeaderboardData(ctx.Request.Context(), grpcReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "GRPC_ERROR",
				Code:      http.StatusInternalServerError,
				Message:   "Failed to fetch leaderboard data",
				Details:   err.Error(),
			},
		})
		return
	}

	if resp.UserId == "" {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "Leaderboard data not found",
				Details:   fmt.Sprintf("No leaderboard data available for userID %s", userID),
			},
		})
		return
	}

	// Collect unique user IDs
	userIDs := make(map[string]struct{}, len(resp.TopKGlobal)+len(resp.TopKEntity)+1)
	userIDs[resp.UserId] = struct{}{}
	for _, user := range resp.TopKGlobal {
		userIDs[user.UserId] = struct{}{}
	}
	for _, user := range resp.TopKEntity {
		userIDs[user.UserId] = struct{}{}
	}

	// Concurrently fetch user profiles
	type profileResult struct {
		id      string
		profile struct {
			UserName  string
			AvatarURL string
		}
		err error
	}

	results := make(chan profileResult, len(userIDs))
	var wg sync.WaitGroup

	for id := range userIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			profileReq := &authUserAdminPB.GetUserProfileRequest{UserID: id}
			profile, err := c.userClient.GetUserProfile(ctx.Request.Context(), profileReq)
			result := profileResult{id: id}
			if err != nil {
				log.Printf("Failed to fetch profile for user %s: %v", id, err)
			} else {
				result.profile = struct {
					UserName  string
					AvatarURL string
				}{UserName: profile.UserProfile.UserName, AvatarURL: profile.UserProfile.AvatarData}
			}
			results <- result
		}(id)
	}

	// Close results channel after all goroutines finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect profiles
	userProfiles := make(map[string]struct {
		UserName  string
		AvatarURL string
	}, len(userIDs))
	for result := range results {
		userProfiles[result.id] = result.profile
	}

	// Construct PascalCase response
	type UserScoreResponse struct {
		UserId    string  `json:"UserId"`
		UserName  string  `json:"UserName"`
		AvatarURL string  `json:"AvatarURL"`
		Score     float64 `json:"Score"`
		Entity    string  `json:"Entity"`
	}

	payload := struct {
		UserId       string              `json:"UserId"`
		UserName     string              `json:"UserName"`
		AvatarURL    string              `json:"AvatarURL"`
		ProblemsDone int                 `json:"ProblemsDone"`
		Score        float64             `json:"Score"`
		Entity       string              `json:"Entity"`
		GlobalRank   int32               `json:"GlobalRank"`
		EntityRank   int32               `json:"EntityRank"`
		TopKGlobal   []UserScoreResponse `json:"TopKGlobal"`
		TopKEntity   []UserScoreResponse `json:"TopKEntity"`
	}{
		UserId:     resp.UserId,
		UserName:   userProfiles[resp.UserId].UserName,
		AvatarURL:  userProfiles[resp.UserId].AvatarURL,
		Score:      resp.Score,
		Entity:     resp.Entity,
		GlobalRank: resp.GlobalRank,
		EntityRank: resp.EntityRank,
		TopKGlobal: make([]UserScoreResponse, len(resp.TopKGlobal)),
		TopKEntity: make([]UserScoreResponse, len(resp.TopKEntity)),
	}

	for i, user := range resp.TopKGlobal {
		payload.TopKGlobal[i] = UserScoreResponse{
			UserId:    user.UserId,
			UserName:  userProfiles[user.UserId].UserName,
			AvatarURL: userProfiles[user.UserId].AvatarURL,
			Score:     user.Score,
			Entity:    user.Entity,
		}
	}

	for i, user := range resp.TopKEntity {
		payload.TopKEntity[i] = UserScoreResponse{
			UserId:    user.UserId,
			UserName:  userProfiles[user.UserId].UserName,
			AvatarURL: userProfiles[user.UserId].AvatarURL,
			Score:     user.Score,
			Entity:    user.Entity,
		}
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: payload,
		Error:   nil,
	})
}

func (u *ProblemController) GetBulkProblemMetadata(c *gin.Context) {
	problemIDs := c.QueryArray("problem_ids")
	if len(problemIDs) == 0 {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing fields, please ensure problem_ids are added as array",
				Details:   "Missing fields, please ensure problem_ids are added as array, Example: ?problem_ids=prob1&problem_ids=prob2",
			},
		})
		return
	}

	req := problemPB.GetBulkProblemMetadataRequest{
		ProblemIds: problemIDs,
	}

	resp, err := u.problemClient.GetBulkProblemMetadata(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   err.Error(),
				Details:   err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error: &model.ErrorInfo{
			ErrorType: "",
			Code:      http.StatusOK,
			Message:   "bulk problems metadata fetched successfully",
			Details:   "bulk problems metadata fetched successfully",
		},
	})
}

func (u *ProblemController) ProblemIDsDoneByUserID(c *gin.Context) {
	var req problemPB.ProblemIDsDoneByUserIDRequest

	// Try to get user_id from query if not provided in JSON
	userID := c.Query("user_id")
	if userID != "" {
		req.UserId = userID
	} else {
		if err := c.ShouldBindJSON(&req); err != nil || req.UserId == "" {
			c.JSON(http.StatusBadRequest, model.GenericResponse{
				Success: false,
				Status:  http.StatusBadRequest,
				Payload: nil,
				Error: &model.ErrorInfo{
					ErrorType: customerrors.ERR_INVALID_REQUEST,
					Code:      http.StatusBadRequest,
					Message:   "provide user_id",
					Details:   "provide user_id in query or JSON body",
				},
			})
			return
		}
	}

	resp, err := u.problemClient.ProblemIDsDoneByUserID(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   err.Error(),
				Details:   err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error: &model.ErrorInfo{
			ErrorType: "",
			Code:      http.StatusOK,
			Message:   "ProblemIDsDoneByUserID fetched successfully",
			Details:   "ProblemIDsDoneByUserID fetched successfully",
		},
	})
}

func (u *ProblemController) VerifyProblemExistenceBulk(c *gin.Context) {
	var req problemPB.VerifyProblemExistenceBulkRequest

	if err := c.ShouldBindJSON(&req); err != nil || len(req.ProblemIds) == 0 {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "provide problem_ids",
				Details:   "provide problem_ids",
			},
		})
		return
	}

	resp, err := u.problemClient.VerifyProblemExistenceBulk(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   err.Error(),
				Details:   err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error: &model.ErrorInfo{
			ErrorType: "",
			Code:      http.StatusOK,
			Message:   "VerifyProblemExistenceBulk fetched successfully",
			Details:   "VerifyProblemExistenceBulk fetched successfully",
		},
	})
}

func (u *ProblemController) RandomProblemIDsGenWithDifficultyRatio(c *gin.Context) {
	var req problemPB.RandomProblemIDsGenWithDifficultyRatioRequest

	if err := c.ShouldBindJSON(&req); err != nil || req.GetQnratio() == nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "provide difficulty qnratio:{easy:n,medium:n,hard:n}",
				Details:   "provide difficulty qnratio:{easy:n,medium:n,hard:n}",
			},
		})
		return
	}

	resp, err := u.problemClient.RandomProblemIDsGenWithDifficultyRatio(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   err.Error(),
				Details:   err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error: &model.ErrorInfo{
			ErrorType: "",
			Code:      http.StatusOK,
			Message:   "RandomProblemIDsGenWithDifficultyRatio fetched successfully",
			Details:   "RandomProblemIDsGenWithDifficultyRatio fetched successfully",
		},
	})
}

func (u *ProblemController) ProblemCountMetadata(c *gin.Context) {

	resp, err := u.problemClient.ProblemCountMetadata(c.Request.Context(), &problemPB.ProblemCountMetadataRequest{})
	if err != nil {
		c.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   err.Error(),
				Details:   err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error: &model.ErrorInfo{
			ErrorType: "",
			Code:      http.StatusOK,
			Message:   "ProblemCountMetadata fetched successfully",
			Details:   "ProblemCountMetadata fetched successfully",
		},
	})
}
