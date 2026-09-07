package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/havilz/caelus-cloud/backend/pkg/hasher"
	"github.com/havilz/caelus-cloud/backend/pkg/jwt"
)

type RegisterInput struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	FullName         string `json:"full_name"`
	OrganizationName string `json:"organization_name"`
}

type RegisterOutput struct {
	User         *domain.User         `json:"user"`
	Organization *domain.Organization `json:"organization"`
	Tokens       *jwt.TokenPair       `json:"tokens"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginOutput struct {
	User         *domain.User         `json:"user"`
	Organization *domain.Organization `json:"organization,omitempty"`
	Tokens       *jwt.TokenPair       `json:"tokens"`
}

type Usecase interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterOutput, error)
	Login(ctx context.Context, input LoginInput) (*LoginOutput, error)
	RefreshToken(ctx context.Context, refreshToken string) (*jwt.TokenPair, error)
}

type authUsecase struct {
	userRepo   domain.UserRepository
	orgRepo    domain.OrganizationRepository
	jwtManager jwt.Manager
}

func NewAuthUsecase(userRepo domain.UserRepository, orgRepo domain.OrganizationRepository, jwtManager jwt.Manager) Usecase {
	return &authUsecase{
		userRepo:   userRepo,
		orgRepo:    orgRepo,
		jwtManager: jwtManager,
	}
}

func (u *authUsecase) Register(ctx context.Context, input RegisterInput) (*RegisterOutput, error) {
	if err := validateRegisterInput(&input); err != nil {
		return nil, err
	}

	if err := u.ensureEmailUnique(ctx, input.Email); err != nil {
		return nil, err
	}

	newUser, err := u.createUserEntity(ctx, input.Email, input.Password, input.FullName)
	if err != nil {
		return nil, err
	}

	newOrg, err := u.createOrganizationWithMember(ctx, newUser.ID, input.OrganizationName, input.FullName)
	if err != nil {
		return nil, err
	}
	newOrg.Role = domain.RoleOwner

	tokens, err := u.jwtManager.GenerateTokenPair(newUser, &newOrg.ID)
	if err != nil {
		return nil, err
	}

	return &RegisterOutput{
		User:         newUser,
		Organization: newOrg,
		Tokens:       tokens,
	}, nil
}

func (u *authUsecase) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if input.Email == "" || input.Password == "" {
		return nil, domain.ErrInvalidCredentials
	}

	user, err := u.authenticateUser(ctx, input.Email, input.Password)
	if err != nil {
		return nil, err
	}

	activeOrgID := u.resolveActiveOrganizationID(ctx, user.ID)

	tokens, err := u.jwtManager.GenerateTokenPair(user, activeOrgID)
	if err != nil {
		return nil, err
	}

	var activeOrg *domain.Organization
	if activeOrgID != nil {
		if org, err := u.orgRepo.GetByID(ctx, *activeOrgID); err == nil && org != nil {
			activeOrg = org
			if member, err := u.orgRepo.GetMember(ctx, *activeOrgID, user.ID); err == nil && member != nil {
				activeOrg.Role = member.Role
			} else {
				activeOrg.Role = domain.RoleOwner
			}
		}
	}

	return &LoginOutput{
		User:         user,
		Organization: activeOrg,
		Tokens:       tokens,
	}, nil
}

func (u *authUsecase) RefreshToken(ctx context.Context, refreshToken string) (*jwt.TokenPair, error) {
	claims, err := u.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	user, err := u.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}

	if !user.IsActive {
		return nil, domain.ErrUserInactive
	}

	return u.jwtManager.GenerateTokenPair(user, claims.OrganizationID)
}

func validateRegisterInput(input *RegisterInput) error {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	input.FullName = strings.TrimSpace(input.FullName)
	input.OrganizationName = strings.TrimSpace(input.OrganizationName)

	if input.Email == "" {
		return domain.ErrEmailInvalid
	}
	if _, err := mail.ParseAddress(input.Email); err != nil {
		return domain.ErrEmailInvalid
	}
	if len(input.Password) < 8 {
		return domain.ErrPasswordTooShort
	}
	if input.FullName == "" {
		return domain.ErrBadRequest
	}
	return nil
}

func (u *authUsecase) ensureEmailUnique(ctx context.Context, email string) error {
	existingUser, err := u.userRepo.GetByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return domain.ErrEmailAlreadyInUse
	}
	return nil
}

func (u *authUsecase) createUserEntity(ctx context.Context, email, password, fullName string) (*domain.User, error) {
	passwordHash, err := hasher.Hash(password, nil)
	if err != nil {
		return nil, domain.ErrInternal
	}

	now := time.Now()
	newUser := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		FullName:     fullName,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := u.userRepo.Create(ctx, newUser); err != nil {
		return nil, err
	}

	return newUser, nil
}

func (u *authUsecase) createOrganizationWithMember(ctx context.Context, userID uuid.UUID, orgName, fallbackName string) (*domain.Organization, error) {
	if orgName == "" {
		orgName = fallbackName + "'s Workspace"
	}

	now := time.Now()
	newOrg := &domain.Organization{
		ID:        uuid.New(),
		Name:      orgName,
		Slug:      generateSlug(orgName),
		Tier:      "free",
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := u.orgRepo.Create(ctx, newOrg); err != nil {
		return nil, err
	}

	orgMember := &domain.OrganizationMember{
		ID:             uuid.New(),
		OrganizationID: newOrg.ID,
		UserID:         userID,
		Role:           domain.RoleOwner,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := u.orgRepo.AddMember(ctx, orgMember); err != nil {
		return nil, err
	}

	return newOrg, nil
}

func (u *authUsecase) authenticateUser(ctx context.Context, email, password string) (*domain.User, error) {
	user, err := u.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if err == domain.ErrNotFound {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	match, err := hasher.Compare(password, user.PasswordHash)
	if err != nil || !match {
		return nil, domain.ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, domain.ErrUserInactive
	}

	return user, nil
}

func (u *authUsecase) resolveActiveOrganizationID(ctx context.Context, userID uuid.UUID) *uuid.UUID {
	orgs, err := u.orgRepo.ListByUser(ctx, userID)
	if err == nil && len(orgs) > 0 {
		return &orgs[0].ID
	}
	return nil
}

func generateSlug(name string) string {
	reg := regexp.MustCompile("[^a-zA-Z0-9]+")
	slug := strings.ToLower(reg.ReplaceAllString(name, "-"))
	slug = strings.Trim(slug, "-")

	if slug == "" {
		slug = "workspace"
	}

	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	suffix := hex.EncodeToString(randomBytes)

	return slug + "-" + suffix
}
