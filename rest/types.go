package rest

import "github.com/mmirzaee/userist/models"

type TokenData struct {
	UserId uint
	Roles  map[int][]string
}

type AuthorizedUser struct {
	User        models.User
	Permissions interface{}
	Type        string
}
