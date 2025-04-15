package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
	"xcode/customerrors"
	"xcode/model"

	"github.com/gin-gonic/gin"
	pb "github.com/lijuuu/GlobalProtoXcode/ProblemsService"
	"google.golang.org/grpc/status"
)

type ProblemController struct {
	problemClient pb.ProblemsServiceClient
}

func NewProblemController(problemClient pb.ProblemsServiceClient) *ProblemController {
	return &ProblemController{problemClient: problemClient}
}

func (c *ProblemController) CreateProblemHandler(ctx *gin.Context) {
	var req pb.CreateProblemRequest
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
	resp, err := c.problemClient.DeleteProblem(ctx.Request.Context(), &pb.DeleteProblemRequest{ProblemId: problemID})
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
	resp, err := c.problemClient.GetProblem(ctx.Request.Context(), &pb.GetProblemRequest{ProblemId: problemID})
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

	resp, err := c.problemClient.FullValidationByProblemID(ctx.Request.Context(), &pb.FullValidationByProblemIDRequest{ProblemId: problemID})
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
	resp, err := c.problemClient.GetLanguageSupports(ctx.Request.Context(), &pb.GetLanguageSupportsRequest{ProblemId: problemID})
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

func (c *ProblemController) GetProblemByIDListHandler(ctx *gin.Context) {
	var req pb.GetProblemByIdListRequest
	if page, err := strconv.Atoi(ctx.Query("page")); err == nil && page > 0 {
		req.Page = int32(page)
	}
	if pageSize, err := strconv.Atoi(ctx.Query("page_size")); err == nil && pageSize > 0 {
		req.PageSize = int32(pageSize)
	}
	req.Tags = ctx.QueryArray("tags")
	req.Difficulty = ctx.Query("difficulty")
	req.SearchQuery = ctx.Query("search_query")
	resp, err := c.problemClient.GetProblemByIDList(ctx.Request.Context(), &req)
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
	if err := ctx.ShouldBindJSON(&req); err != nil {
		fmt.Println("bind json failed ", req)

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
	// fmt.Println("no userID")
	// if !exists || userID == nil {
	// 		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
	// 				Success: false,
	// 				Status:  http.StatusBadRequest,
	// 				Payload: nil,
	// 				Error: &model.ErrorInfo{
	// 						ErrorType: customerrors.ERR_BAD_REQUEST,
	// 						Code:      http.StatusBadRequest,
	// 						Message:   "User ID is missing or unauthorized",
	// 						Details:   "Failed to retrieve user ID from context",
	// 				},
	// 		})
	// 		return
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

	// Call the gRPC service
	resp, err := c.problemClient.RunUserCodeProblem(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: map[string]interface{}{
				"problem_id":      resp.ProblemId,
				"language":        resp.Language,
				"is_run_testcase": resp.IsRunTestcase,
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
	if !resp.Success {
		httpCode := http.StatusBadRequest
		switch resp.ErrorType {
		case "NOT_FOUND":
			httpCode = http.StatusNotFound
		case "COMPILATION_ERROR":
			httpCode = http.StatusBadRequest
		case "EXECUTION_ERROR":
			httpCode = http.StatusBadRequest
		default:
			httpCode = http.StatusBadGateway
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
				"problem_id":      resp.ProblemId,
				"language":        resp.Language,
				"is_run_testcase": resp.IsRunTestcase,
				"rawoutput": model.UniversalExecutionResult{
					TotalTestCases:  0,
					PassedTestCases: 0,
					FailedTestCases: 0,
					FailedTestCase: model.TestCaseResult{
						TestCaseIndex: -1,
						Error:         resp.Message,
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
	if err := json.Unmarshal([]byte(resp.Message), &output); err != nil {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: map[string]interface{}{
				"problem_id":      resp.ProblemId,
				"language":        resp.Language,
				"is_run_testcase": resp.IsRunTestcase,
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
			"problem_id":      resp.ProblemId,
			"language":        resp.Language,
			"is_run_testcase": resp.IsRunTestcase,
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
		UserId: userID,
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

