package controller

import (
	"net/http"
	"strconv"
	"xcode/customerrors"
	"xcode/middleware"
	"xcode/model"

	"github.com/gin-gonic/gin"
	challengePB "github.com/lijuuu/GlobalProtoXcode/ChallengeService"
	problemPB "github.com/lijuuu/GlobalProtoXcode/ProblemsService"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ChallengeController struct {
	challengeClient      challengePB.ChallengeServiceClient
	problemClient problemPB.ProblemsServiceClient
}

func NewChallengeController(challengeClient challengePB.ChallengeServiceClient, problemClient problemPB.ProblemsServiceClient) *ChallengeController {
	return &ChallengeController{
		problemClient: problemClient,
		challengeClient:      challengeClient,
	}
}

//start challenge
//join challenge
//public challenge history
//private challenge history
//open public challenges
//join private challenge -> get session hash for direct wss conn to challenge service.

func (c *ChallengeController) CreateChallenge(ctx *gin.Context) {
	var req problemPB.CreateChallengeRequest
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

func (c *ChallengeController) GetChallengeDetails(ctx *gin.Context) {
	var req problemPB.GetChallengeDetailsRequest
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

func (c *ChallengeController) GetPublicChallenge(ctx *gin.Context) {
	req := &problemPB.GetPublicChallengesRequest{}
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

func (c *ChallengeController) JoinChallenge(ctx *gin.Context) {
	var req problemPB.JoinChallengeRequest
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

func (c *ChallengeController) StartChallenge(ctx *gin.Context) {
	var req problemPB.StartChallengeRequest
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

func (c *ChallengeController) EndChallenge(ctx *gin.Context) {
	var req problemPB.EndChallengeRequest
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

func (c *ChallengeController) GetSubmissionStatus(ctx *gin.Context) {
	var req problemPB.GetSubmissionStatusRequest
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

func (c *ChallengeController) GetChallengeSubmissions(ctx *gin.Context) {
	var req problemPB.GetChallengeSubmissionsRequest
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

func (c *ChallengeController) GetUserStats(ctx *gin.Context) {
	var req problemPB.GetUserStatsRequest
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

func (c *ChallengeController) GetChallengeUserStats(ctx *gin.Context) {
	var req problemPB.GetChallengeUserStatsRequest
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

func (c *ChallengeController) GetUserChallengeHistory(ctx *gin.Context) {
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
	grpcReq := &problemPB.GetChallengeHistoryRequest{
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
