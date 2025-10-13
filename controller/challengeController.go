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

	req.CreatedAt = time.Now().Unix()

	// get creator id from context
	userId, ok := middleware.GetEntityID(ctx)
	if !ok || userId == "" {
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
	req.CreatorId = userId

	// set default status
	if req.Status == "" {
		req.Status = model.ChallengeOpen
	}

	// enforce min time limit
	if req.TimeLimitMillis < 1200 {
		req.TimeLimitMillis = 1200
	}

	// ensure config is not nil
	if req.Config == nil {
		req.Config = &challengePB.ChallengeConfig{}
	}

	// if user provided problem ids, verify them
	if len(req.ProcessedProblemIds) > 0 && len(req.ProcessedProblemIds) <= 10 {
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
					Message:   "some problems do not exist or problem threshold reached",
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
		resp, err := c.problemClient.RandomProblemIdsGenWithDifficultyRatio(ctx, &problemPB.RandomProblemIdsGenWithDifficultyRatioRequest{
			QnRatio: &problemPB.ProblemDifficultyRatio{
				Easy:   req.Config.MaxEasyQuestions,
				Medium: req.Config.MaxMediumQuestions,
				Hard:   req.Config.MaxHardQuestions,
			},
		})
		if err != nil || resp == nil || resp.ErrorType == "INSUFFICIENT_PROBLEMS" {
			grpcStatus, _ := status.FromError(err)
			errorType := ""
			if resp != nil {
				errorType = resp.ErrorType
			}
			ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
				Success: false,
				Status:  http.StatusInternalServerError,
				Error: &model.ErrorInfo{
					ErrorType: "grpc_error",
					Code:      http.StatusInternalServerError,
					Message:   "failed to generate problems : " + errorType,
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

func (c *ChallengeController) GetActiveOpenChallenges(ctx *gin.Context) {
	req := &challengePB.PaginationRequest{}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "10"))
	req.Page = int32(page)
	req.PageSize = int32(pageSize)

	resp, err := c.challengeClient.GetActiveOpenChallenges(ctx.Request.Context(), req)
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

func (c *ChallengeController) AbandonChallenge(ctx *gin.Context) {
	var req struct {
		CreatorId   string `json:"creatorId"`
		ChallengeId string `json:"challengeId"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil || req.CreatorId == "" || req.ChallengeId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "invalid request: missing creatorId or challengeId",
			},
		})
		return
	}

	grpcReq := &challengePB.AbandonChallengeRequest{
		CreatorId:   req.CreatorId,
		ChallengeId: req.ChallengeId,
	}

	resp, err := c.challengeClient.AbandonChallenge(ctx.Request.Context(), grpcReq)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Error: &model.ErrorInfo{
				ErrorType: "grpc_error",
				Code:      http.StatusInternalServerError,
				Message:   grpcStatus.Message(),
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
	})
}

func (c *ChallengeController) GetChallengeHistory(ctx *gin.Context) {
	userId, _ := middleware.GetEntityID(ctx)
	if userId == "" {
		ctx.JSON(http.StatusBadRequest, model.GenericResponse{Success: false, Status: http.StatusBadRequest, Error: &model.ErrorInfo{Message: "unauthorized request, check your token"}})
		return
	}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "10"))
	isPrivateStr := ctx.DefaultQuery("isPrivate", "true")
	isPrivate := false
	if isPrivateStr == "true" {
		isPrivate = true
	} //default to isPrivate false get public history unless specified.

	req := &challengePB.GetChallengeHistoryRequest{
		UserId: userId,
		Pagination: &challengePB.PaginationRequest{
			Page:     int32(page),
			PageSize: int32(pageSize),
		},
		IsPrivate: isPrivate,
	}

	resp, err := c.challengeClient.GetChallengeHistory(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusInternalServerError, Error: &model.ErrorInfo{Message: grpcStatus.Message()}})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}

func (c *ChallengeController) GetOwnersActiveChallenges(ctx *gin.Context) {

	userId, ok := ctx.Get(middleware.EntityIDKey)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusBadRequest, Error: &model.ErrorInfo{Message: "unauthorized request"}})
		return
	}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "10"))

	req := &challengePB.GetOwnersActiveChallengesRequest{
		UserId: userId.(string),
		Pagination: &challengePB.PaginationRequest{
			Page:     int32(page),
			PageSize: int32(pageSize),
		},
	}

	resp, err := c.challengeClient.GetOwnersActiveChallenges(ctx.Request.Context(), req)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		ctx.JSON(http.StatusInternalServerError, model.GenericResponse{Success: false, Status: http.StatusInternalServerError, Error: &model.ErrorInfo{Message: grpcStatus.Message()}})
		return
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{Success: true, Status: http.StatusOK, Payload: resp})
}
