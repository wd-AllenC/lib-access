package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ddliu/go-httpclient"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"gopkg.in/guregu/null.v4"
)

type DippClaims struct {
	Roles    []string `json:"roles"`
	Brands   []string `json:"brands"`
	Agencies []string `json:"agencies"`
	Email    string   `json:"email"`
	Role     string   `json:"role"`
	jwt.RegisteredClaims
}

type Access struct {
	claims   *DippClaims
	brands   map[string]bool
	agencies map[string]bool
	roles    map[string]bool
}

const (
	BrandRole           string = "brand"
	AgencyAdminRole            = "agency_admin"
	AgencyOwner                = "agency_owner"
	DippAgencyAdminRole        = "dipp_agency_admin"
	DippAgencyOwnerRole        = "dipp_agency_owner"
)

// New creates and returns a new *Access wrapper around the given *jwt.Token.
func New(user *jwt.Token) *Access {
	claims := user.Claims.(*DippClaims)
	if claims == nil {
		claims = &DippClaims{}
	}

	a := Access{
		claims,
		map[string]bool{},
		map[string]bool{},
		map[string]bool{},
	}

	for _, ac := range a.claims.Agencies {
		a.agencies[ac] = true
	}

	for _, b := range a.claims.Brands {
		a.brands[b] = true
	}

	for _, r := range a.claims.Roles {
		a.roles[r] = true
	}

	return &a
}

// NewWithEcho does the same as access.New but receives an echo.Context instead of a *jwt.Token.
func NewWithEcho(c echo.Context) *Access {
	return New(c.Get("user").(*jwt.Token))
}

func (a *Access) Brand(uuid string) bool {
	return a.brands[uuid]
}

func (a *Access) Agency(uuid string) bool {
	return a.agencies[uuid]
}

func (a *Access) Role(uuid string) bool {
	return a.roles[uuid]
}

func (a *Access) User(uuid string) bool {
	return a.claims.Subject == uuid
}

func (a *Access) CurrentUser() string {
	return a.claims.Subject
}

func (a *Access) Email() string {
	return a.claims.Email
}

type LegacyError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type LegacyErrorResponse struct {
	Code    int           `json:"code"`
	Errors  []LegacyError `json:"errors"`
	Message string        `json:"message"`
}

// TokenError is used to return error with error occurred JWT token when processing JWT token
type TokenError struct {
	Token *jwt.Token
	Err   error
}

// Error implements error.
func (*TokenError) Error() string {
	panic("unimplemented error")
}

type VerifyApiKeyResponse struct {
	Email    string   `json:"email"`
	Status   string   `json:"status"`
	AgencyID null.Int `json:"agency_id"`
	UUID     string   `json:"uuid"`
	Brands   []string `json:"brands"`
	Agencies []string `json:"agencies"`
	Role     string   `json:"role,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// AccessMiddleware returns an echo.MiddlewareFunc that checks for a valid JWT token in the Authorization header.
func AccessMiddleware(rdb *redis.Client, authHost string, key string) echo.MiddlewareFunc {
	jwtConfig := echojwt.Config{
		SigningKey:  []byte(key),
		TokenLookup: "header:Authorization:Bearer ,header:X-API-KEY",
		ErrorHandler: func(c echo.Context, err error) error {
			legacyErrRes := LegacyErrorResponse{
				Code: http.StatusForbidden,
				Errors: []LegacyError{{
					Field:   "INVALID_JSON_WEB_TOKEN",
					Message: err.Error(),
				}},
				Message: "You don't have the permission to access the requested resource.",
			}
			return c.JSON(http.StatusForbidden, legacyErrRes)
		},
		// NewClaimsFunc: func(c echo.Context) jwt.Claims {
		// 	return &DippClaims{}
		// },
		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
			// custom token parser
			if c.Request().Header.Get("X-API-Key") != "" {

				authUrl := fmt.Sprintf("%s/api/v1/auth/verify-api-key", authHost)
				// post auth API
				authResponse, err := httpclient.
					Begin().
					WithOption(httpclient.OPT_TIMEOUT, 30).
					WithHeaders(map[string]string{
						"X-API-KEY": c.Request().Header.Get("X-API-Key"),
					}).
					Post(authUrl, nil)

				if err != nil {
					return nil, err
				}

				if authResponse.StatusCode != http.StatusOK {
					errMsg := fmt.Sprintf("Failed to verify auth an error code: %d", authResponse.StatusCode)
					return nil, errors.New(errMsg)
				}

				responseBody, err := authResponse.ReadAll()
				if err != nil {
					return nil, err
				}

				account := &VerifyApiKeyResponse{}
				if err = json.Unmarshal(responseBody, account); err != nil {
					return nil, err
				}

				jti := uuid.NewString()
				claim := &DippClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   account.UUID,
						ID:        jti,
						Issuer:    "private api",
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						NotBefore: jwt.NewNumericDate(time.Now()),
						// ExpiresAt: jwt.NewNumericDate(time.Now().Add(500000000)),
					},
					Email:    account.Email,
					Agencies: account.Agencies,
					Brands:   account.Brands,
					Roles:    account.Roles,
					Role:     account.Role,
				}

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
				// return token, nil

				accessToken, err := token.SignedString([]byte(key))
				if err != nil {
					return nil, err
				}
				keyFunc := func(t *jwt.Token) (interface{}, error) {
					if t.Method.Alg() != "HS256" {
						return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
					}
					return []byte(key), nil
				}

				// pretend the access token for the in any api call deeply
				c.Request().Header.Set("Authorization", "Bearer "+accessToken)

				newToken, err := jwt.ParseWithClaims(accessToken, &DippClaims{}, keyFunc)
				if err != nil {
					return nil, &TokenError{Token: newToken, Err: err}
				}
				if !newToken.Valid {
					return nil, &TokenError{Token: newToken, Err: errors.New("invalid token")}
				}

				return newToken, nil
			} else {

				keyFunc := func(t *jwt.Token) (interface{}, error) {
					if t.Method.Alg() != "HS256" {
						return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
					}
					return []byte(key), nil
				}

				token, err := jwt.ParseWithClaims(auth, &DippClaims{}, keyFunc)
				if err != nil {
					return nil, &TokenError{Token: token, Err: err}
				}
				if !token.Valid {
					return nil, &TokenError{Token: token, Err: errors.New("invalid token")}
				}

				if rdb != nil {
					// existing logic that check redis record is been revoked or not
					claims := token.Claims.(jwt.MapClaims)
					isRevoked, err := rdb.Get(c.Request().Context(), claims["jti"].(string)).Result()
					if err != nil || isRevoked == "true" {
						return nil, errors.New("token has been revoked")
					}
				}

				return token, nil
			}
		},
	}

	return echojwt.WithConfig(jwtConfig)
}
