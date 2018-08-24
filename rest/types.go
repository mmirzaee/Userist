package rest

import "github.com/mmirzaee/userist/models"

// TokenData - token data structure
type TokenData struct {
	UserId uint
	Roles  map[int][]string
}

// AuthorizedUser - authorized user data structure
type AuthorizedUser struct {
	User        models.User
	Permissions interface{}
	Type        string
}
