package rest

import (
	"net/http"
	"github.com/mmirzaee/userist/models"
	"fmt"
)

func PostAuthLogin(w http.ResponseWriter, r *http.Request, _ AuthorizedUser, _ int) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		JsonHttpRespond(w, nil, "invalid inputs", http.StatusForbidden)
		return
	}

	user, err := models.GetUserByUsername(username)
	if err != nil {
		JsonHttpRespond(w, nil, "username not found", http.StatusNotFound)
		return
	}

	isValidPassword := CheckPasswordHash(password, user.Password)

	if !isValidPassword {
		JsonHttpRespond(w, nil, "username or password is wrong", http.StatusForbidden)
		return
	}

	var roles = models.GetUserTenantsPermissions(user.UserTenantRoles)
	token := GenerateToken(TokenData{UserId: user.ID, Roles: roles})
	userSafeData := user.Safe()
	userSafeData["Token"] = token
	userSafeData["Tenants"] = models.GetUserTenants(user.ID)
	JsonHttpRespond(w, userSafeData, "", http.StatusOK)
}

func PostRefreshToken(w http.ResponseWriter, r *http.Request, user AuthorizedUser, _ int) {
	fmt.Println(user)
	refreshUser, err := models.GetUserByID(user.User.ID)
	if err != nil {
		JsonHttpRespond(w, nil, "username not found", http.StatusNotFound)
		return
	}

	var roles = models.GetUserTenantsPermissions(refreshUser.UserTenantRoles)
	token := GenerateToken(TokenData{UserId: refreshUser.ID, Roles: roles})
	userSafeData := refreshUser.Safe()
	userSafeData["Token"] = token
	userSafeData["Tenants"] = models.GetUserTenants(refreshUser.ID)
	JsonHttpRespond(w, userSafeData, "", http.StatusOK)
}

func PostAuthCheckToken(w http.ResponseWriter, r *http.Request, user AuthorizedUser, _ int) {
	u, _ := models.GetUserByID(user.User.ID)
	JsonHttpRespond(w, u.Safe(), "", http.StatusOK)
}
