package controller

import (
	"net/http"
	"strconv"
	"time"

	"xcode/customerrors"
	"xcode/middleware"
	"xcode/model"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	challengePB "github.com/lijuuu/GlobalProtoXcode/ChallengeService"
	problemPB "github.com/lijuuu/GlobalProtoXcode/ProblemsService"

	"google.golang.org/grpc/status"
)

type ChallengeController struct {
	challengeClient challengePB.ChallengeServiceClient
	problemClient   problemPB.ProblemsServiceClient
}

func NewChallengeController(challengeClient challengePB.ChallengeServiceClient, problemClient problemPB.ProblemsServiceClient) *ChallengeController {
	return &ChallengeController{
		challengeClient: challengeClient,
		problemClient:   problemClient,
	}
}

func (c *ChallengeController) CreateChallenge(ctx *gin.Context) {
	var req challengePB.ChallengeRecord

	// bind json and validate title
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Title == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "invalid request: missing or invalid title",
				Details:   err.Error(),
			},
		})
		return
	}

	// check title length
	if len(req.Title) < 3 {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "title must be at least 3 characters",
			},
		})
		return
	}

	// generate challenge id
	req.ChallengeId = uuid.New().String()

	// get creator id from context
	userID, ok := middleware.GetEntityID(ctx)
	if !ok || userID == "" {
		ctx.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "unauthorized: missing user id",
			},
		})
		return
	}
	req.CreatorId = userID

	// set default status
	if req.Status == "" {
		req.Status = "pending"
	}

	// enforce min time limit
	if req.TimeLimitMillis < 10000 {
		req.TimeLimitMillis = 10000
	}

	// set default start time if invalid or too soon
	nowPlus5Min := time.Now().Add(5 * time.Minute).Unix()
	if req.StartTimeUnix == 0 || req.StartTimeUnix < nowPlus5Min {
		req.StartTimeUnix = nowPlus5Min
	}

	// ensure config is not nil
	if req.Config == nil {
		req.Config = &challengePB.ChallengeConfig{}
	}

	// if user provided problem ids, verify them
	if len(req.ProcessedProblemIds) > 0 {
		_, err := c.problemClient.VerifyProblemExistenceBulk(ctx, &problemPB.VerifyProblemExistenceBulkRequest{
			ProblemIds: req.ProcessedProblemIds,
		})
		if err != nil {
			grpcStatus, _ := status.FromError(err)
			ctx.JSON(http.StatusBadRequest, model.GenericResponse{
				Success: false,
				Status:  http.StatusBadRequest,
				Error: &model.ErrorInfo{
					ErrorType: "grpc_error",
					Code:      http.StatusBadRequest,
					Message:   "some problems do not exist",
					Details:   grpcStatus.Message(),
				},
			})
			return
		}
	} else {
		// if no ratio provided, default to 1 easy
		if req.Config.MaxEasyQuestions == 0 && req.Config.MaxMediumQuestions == 0 && req.Config.MaxHardQuestions == 0 {
			req.Config.MaxEasyQuestions = 1
		}

		// generate problems from difficulty ratio
		resp, err := c.problemClient.RandomProblemIDsGenWithDifficultyRatio(ctx, &problemPB.RandomProblemIDsGenWithDifficultyRatioRequest{
			Qnratio: &problemPB.ProblemDifficultyRatio{
				Easy:   req.Config.MaxEasyQuestions,
				Medium: req.Config.MaxMediumQuestions,
				Hard:   req.Config.MaxHardQuestions,
			},
		})
		if err != nil {
			grpcStatus, _ := status.FromError(err)
			ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
				Success: false,
				Status:  http.StatusInternalServerError,
				Error: &model.ErrorInfo{
					ErrorType: "grpc_error",
					Code:      http.StatusInternalServerError,
					Message:   "failed to generate problems",
					Details:   grpcStatus.Message(),
				},
			})
			return
		}
		req.ProcessedProblemIds = resp.ProblemIds
	}

	// create challenge via grpc
	resp, err := c.challengeClient.CreateChallenge(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Error: &model.ErrorInfo{
				ErrorType: "grpc_error",
				Code:      http.StatusBadRequest,
				Message:   "failed to create challenge",
				Details:   grpcStatus.Message(),
			},
		})
		return
	}

	// return success response
	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
	})
}

func (c *ChallengeController) GetPublicChallenges(ctx *gin.Context) {
	req := &challengePB.PaginationRequest{}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))
	req.Page = int32(page)
	req.PageSize = int32(pageSize)

	resp, err := c.challengeClient.GetPublicChallenges(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Error:   &model.ErrorInfo{ErrorType: "GRPC_ERROR", Message: grpcStatus.Message()},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}

func (c *ChallengeController) GetPrivateChallengesOfUser(ctx *gin.Context) {
	userID := ctx.Query("user_id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{Success: false, Status: http.StatusBadRequest, Error: &model.ErrorInfo{Message: "user_id required"}})
		return
	}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))

	req := &challengePB.PrivateChallengesRequest{
		UserId: userID,
		Pagination: &challengePB.PaginationRequest{
			Page:     int32(page),
			PageSize: int32(pageSize),
		},
	}

	resp, err := c.challengeClient.GetPrivateChallengesOfUser(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusInternalServerError, Error: &model.ErrorInfo{Message: grpcStatus.Message()}})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}

func (c *ChallengeController) GetActiveChallenges(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))

	req := &challengePB.PaginationRequest{
		Page:     int32(page),
		PageSize: int32(pageSize),
	}

	resp, err := c.challengeClient.GetActiveChallenges(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusInternalServerError, Error: &model.ErrorInfo{Message: grpcStatus.Message()}})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}

func (c *ChallengeController) GetUserChallenges(ctx *gin.Context) {
	userID := ctx.Query("user_id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{Success: false, Status: http.StatusBadRequest, Error: &model.ErrorInfo{Message: "user_id required"}})
		return
	}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "10"))

	req := &challengePB.UserChallengesRequest{
		UserId: userID,
		Pagination: &challengePB.PaginationRequest{
			Page:     int32(page),
			PageSize: int32(pageSize),
		},
	}

	resp, err := c.challengeClient.GetUserChallenges(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusInternalServerError, Error: &model.ErrorInfo{Message: grpcStatus.Message()}})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}

func (c *ChallengeController) PushSubmissionStatus(ctx *gin.Context) {
	var req challengePB.PushSubmissionStatusRequest
	req.TraceId = GetTraceID(&ctx.Request.Header)

	if err := ctx.ShouldBindJSON(&req); err != nil || req.ChallengeId == "" || req.UserId == "" || req.ProblemId == "" || req.Status == "" || req.SubmissionId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{Success: false, Status: http.StatusBadRequest, Error: &model.ErrorInfo{Message: "Missing required fields or invalid JSON"}})
		return
	}

	resp, err := c.challengeClient.PushSubmissionStatus(ctx.Request.Context(), &req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusInternalServerError, Error: &model.ErrorInfo{Message: grpcStatus.Message()}})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}
