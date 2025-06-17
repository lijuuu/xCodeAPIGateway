package gamemanager

type Challenge struct {
	ChallengeId      string
	CreatorId        string
	Title            string
	IsPrivate        string
	Password         string
	Status           string
	ProblemArray     []string
	TimeLimit        string
	ParticipantArray []ParticipantMetadata
	WinnerId         ParticipantMetadata
}

type ParticipantMetadata struct {
	UserId            string
	ProblemsDone      int
	ProblemsAttempted int
}
