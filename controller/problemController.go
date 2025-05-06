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
	"xcode/middleware"
	"xcode/model"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	pb "github.com/lijuuu/GlobalProtoXcode/ProblemsService"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ProblemController struct {
	problemClient pb.ProblemsServiceClient
	userClient    AuthUserAdminService.AuthUserAdminServiceClient
}

func NewProblemController(problemClient pb.ProblemsServiceClient, userClient AuthUserAdminService.AuthUserAdminServiceClient) *ProblemController {
	return &ProblemController{problemClient: problemClient, userClient: userClient}
}

func (c *ProblemController) CreateProblemHandler(ctx *gin.Context) {
	var req pb.CreateProblemRequest
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
	var req pb.UpdateProblemRequest
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
	resp, err := c.problemClient.DeleteProblem(ctx.Request.Context(), &pb.DeleteProblemRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
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
	resp, err := c.problemClient.GetProblem(ctx.Request.Context(), &pb.GetProblemRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
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
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Problem,
		Error:   nil,
	})
}

func (c *ProblemController) ListProblemsHandler(ctx *gin.Context) {
	var req pb.ListProblemsRequest
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
	var req pb.AddTestCasesRequest
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
	var req pb.DeleteTestCaseRequest
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
	var req pb.AddLanguageSupportRequest
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
	var req pb.UpdateLanguageSupportRequest
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
	var req pb.RemoveLanguageSupportRequest
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

	resp, err := c.problemClient.FullValidationByProblemID(ctx.Request.Context(), &pb.FullValidationByProblemIDRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
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
	resp, err := c.problemClient.GetLanguageSupports(ctx.Request.Context(), &pb.GetLanguageSupportsRequest{ProblemId: problemID, TraceID: GetTraceID(&ctx.Request.Header)})
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
	req := &pb.GetProblemByIdSlugRequest{
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
	var req pb.GetProblemMetadataListRequest
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
	var req pb.RunProblemRequest
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

	getUserProfileRequest := &AuthUserAdminService.GetUserProfileRequest{
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
	grpcReq := pb.GetSubmissionsRequest{
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

func mapSubmissions(pbSubmissions []*pb.Submission) []model.Submission {
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

func convertTimestampToTime(pbTimestamp *pb.Timestamp) time.Time {
	// pb.RunProblemRequest
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
	grpcReq := &pb.GetProblemsDoneStatisticsRequest{
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

	grpcReq := &pb.GetMonthlyActivityHeatmapRequest{
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

	grpcReq := &pb.GetTopKGlobalRequest{
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

	grpcReq := &pb.GetTopKEntityRequest{
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

	grpcReq := &pb.GetUserRankRequest{
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

	grpcReq := &pb.GetLeaderboardDataRequest{
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
			profileReq := &AuthUserAdminService.GetUserProfileRequest{UserID: id}
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

func (c *ProblemController) CreateChallenge(ctx *gin.Context) {
	var req pb.CreateChallengeRequest
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

	userID, _ := ctx.Get(middleware.EntityIDKey)
	req.CreatorId = userID.(string)

	resp, err := c.problemClient.CreateChallenge(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to create challenge", Details: grpcStatus.Message()},
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

func (c *ProblemController) GetChallengeDetails(ctx *gin.Context) {
	var req pb.GetChallengeDetailsRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	req.Id = ctx.Query("challenge_id")
	// req.UserId = ctx.Query("user_id")

	if req.Id == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: "challenge_id and user_id are required"},
		})
		return
	}

	resp, err := c.problemClient.GetChallengeDetails(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: httpCode, Message: "Failed to fetch challenge details", Details: grpcStatus.Message()},
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

func (c *ProblemController) GetPublicChallenge(ctx *gin.Context) {
	req := &pb.GetPublicChallengesRequest{}
	req.TraceID = GetTraceID(&ctx.Request.Header)

	req.UserId = ctx.Query("user_id")
	req.Difficulty = ctx.Query("difficulty")
	req.IsActive = ctx.DefaultQuery("is_active", "false") == "true"

	page, err := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	if err != nil {
		page = 1
	}
	req.Page = int32(page)

	pageSize, err := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	if err != nil {
		pageSize = 10
	}
	req.PageSize = int32(pageSize)

	resp, err := c.problemClient.GetPublicChallenges(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to fetch challenges", Details: grpcStatus.Message()},
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

func (c *ProblemController) JoinChallenge(ctx *gin.Context) {
	var req pb.JoinChallengeRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)
	req.UserId = ctx.MustGet(middleware.EntityIDKey).(string)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: customerrors.ERR_INVALID_REQUEST, Code: http.StatusBadRequest, Message: "Invalid request", Details: err.Error()},
		})
		return
	}

	resp, err := c.problemClient.JoinChallenge(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusBadRequest
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: httpCode, Message: "Failed to join challenge", Details: grpcStatus.Message()},
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

func (c *ProblemController) StartChallenge(ctx *gin.Context) {
	var req pb.StartChallengeRequest
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

	userID, _ := ctx.Get(middleware.EntityIDKey)
	req.UserId = userID.(string)

	resp, err := c.problemClient.StartChallenge(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Code: http.StatusBadRequest, Message: "Failed to start challenge", Details: grpcStatus.Message()},
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

func (c *ProblemController) EndChallenge(ctx *gin.Context) {
	var req pb.EndChallengeRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil || req.ChallengeId == "" || req.UserId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   "challenge_id and user_id are required",
			},
		})
		return
	}

	resp, err := c.problemClient.EndChallenge(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		} else if grpcStatus.Code() == codes.InvalidArgument {
			httpCode = http.StatusBadRequest
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      httpCode,
				Message:   "Failed to end challenge",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	if len(resp.Leaderboard) == 0 {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_RESPONSE,
				Code:      http.StatusBadRequest,
				Message:   "Invalid response from service",
				Details:   "Leaderboard data is empty",
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"message":     "Challenge ended successfully",
			"leaderboard": resp.Leaderboard,
		},
		Error: nil,
	})
}

func (c *ProblemController) GetSubmissionStatus(ctx *gin.Context) {
	var req pb.GetSubmissionStatusRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	req.SubmissionId = ctx.Query("submission_id")
	if req.SubmissionId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      http.StatusBadRequest,
				Message:   "Failed to get submission status",
				Details:   "submission_id is required",
			},
		})
		return
	}

	resp, err := c.problemClient.GetSubmissionStatus(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      httpCode,
				Message:   "Failed to get submission status",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	if resp.Submission == nil || resp.Submission.Id == "" {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   "Submission not found",
				Details:   "Submission data is missing or invalid",
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Submission,
		Error:   nil,
	})
}

func (c *ProblemController) GetChallengeSubmissions(ctx *gin.Context) {
	var req pb.GetChallengeSubmissionsRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	req.ChallengeId = ctx.Query("challenge_id")
	if req.ChallengeId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   "challenge_id is required",
			},
		})
		return
	}

	resp, err := c.problemClient.GetChallengeSubmissions(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      httpCode,
				Message:   "Failed to get challenge submissions",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	if resp.Submissions == nil {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   "No submissions found",
				Details:   "Submissions data is missing",
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Submissions,
		Error:   nil,
	})
}

func (c *ProblemController) GetUserStats(ctx *gin.Context) {
	var req pb.GetUserStatsRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	req.UserId = ctx.Query("user_id")
	if req.UserId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   "user_id is required",
			},
		})
		return
	}

	resp, err := c.problemClient.GetUserStats(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      httpCode,
				Message:   "Failed to get user stats",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	if resp.Stats == nil || resp.Stats.UserId == "" {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   "User stats not found",
				Details:   "Stats data is missing or invalid",
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp.Stats,
		Error:   nil,
	})
}

func (c *ProblemController) GetChallengeUserStats(ctx *gin.Context) {
	var req pb.GetChallengeUserStatsRequest
	req.TraceID = GetTraceID(&ctx.Request.Header)

	req.ChallengeId = ctx.Query("challenge_id")
	req.UserId = ctx.Query("user_id")
	if req.ChallengeId == "" || req.UserId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   "challenge_id and user_id are required",
			},
		})
		return
	}

	resp, err := c.problemClient.GetChallengeUserStats(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      httpCode,
				Message:   "Failed to get challenge user stats",
				Details:   grpcStatus.Message(),
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
				ErrorType: customerrors.ERR_NOT_FOUND,
				Code:      http.StatusNotFound,
				Message:   "Challenge user stats not found",
				Details:   "User stats data is missing or invalid",
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

func (c *ProblemController) GetUserChallengeHistory(ctx *gin.Context) {
	// Extract query parameters
	pageStr := ctx.Query("page")
	isPrivate := ctx.Query("is_private")
	pageSizeStr := ctx.Query("page_size")

	userIDIntr, _ := ctx.Get(middleware.EntityIDKey)
	userID, _ := userIDIntr.(string)

	// Validate user_id
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing required field: user_id",
				Details:   "The user_id query parameter is required",
			},
		})
		return
	}

	// Parse pagination parameters
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1 // Default to page 1
	}
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 {
		pageSize = 10 // Default to 10 items per page
	}

	private := false
	if isPrivate == "true" {
		private = true
	}

	// Prepare gRPC request
	grpcReq := &pb.GetChallengeHistoryRequest{
		UserId:    userID,
		Page:      int32(page),
		PageSize:  int32(pageSize),
		IsPrivate: &private,
		TraceID:   GetTraceID(&ctx.Request.Header),
	}

	// Call gRPC service
	resp, err := c.problemClient.GetChallengeHistory(ctx.Request.Context(), grpcReq)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		httpCode := http.StatusInternalServerError
		if grpcStatus.Code() == codes.InvalidArgument {
			httpCode = http.StatusBadRequest
		} else if grpcStatus.Code() == codes.NotFound {
			httpCode = http.StatusNotFound
		}
		ctx.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_GRPC_ERROR,
				Code:      httpCode,
				Message:   "Failed to fetch challenge history",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	// Successful response
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"challenges":  resp.Challenges,
			"total_count": resp.TotalCount,
			"page":        resp.Page,
			"page_size":   resp.PageSize,
			"message":     "",
		},
		Error: nil,
	})
}

func (u *ProblemController) GetBulkProblemMetadata(c *gin.Context) {
	var req pb.GetBulkProblemMetadataRequest

	if err := c.ShouldBindJSON(&req); err != nil || len(req.ProblemIds) == 0 {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Missing fields, please ensure problem_ids are added as array",
				Details:   "Missing fields, please ensure problem_ids are added as array, Example problem_ids:[prob1,prob2....]",
			},
		})
		return
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
