package rest

import (
	"fmt"
	"github.com/mmirzaee/userist/models"
	"net/http"
)

func postAuthLogin(w http.ResponseWriter, r *http.Request, _ AuthorizedUser, _ int) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		jsonHttpRespond(w, nil, "invalid inputs", http.StatusForbidden)
		return
	}

	user, err := models.GetUserByUsername(username)
	if err != nil {
		jsonHttpRespond(w, nil, "username not found", http.StatusNotFound)
		return
	}

	isValidPassword := checkPasswordHash(password, user.Password)

	if !isValidPassword {
		jsonHttpRespond(w, nil, "username or password is wrong", http.StatusForbidden)
		return
	}

	var roles = models.GetUserTenantsPermissions(user.UserTenantRoles)
	token := generateToken(TokenData{UserId: user.ID, Roles: roles})
	userSafeData := user.Safe()
	userSafeData["Token"] = token
	userSafeData["Tenants"] = models.GetUserTenants(user.ID)
	jsonHttpRespond(w, userSafeData, "", http.StatusOK)
}

func postRefreshToken(w http.ResponseWriter, r *http.Request, user AuthorizedUser, _ int) {
	fmt.Println(user)
	refreshUser, err := models.GetUserByID(user.User.ID)
	if err != nil {
		jsonHttpRespond(w, nil, "username not found", http.StatusNotFound)
		return
	}

	var roles = models.GetUserTenantsPermissions(refreshUser.UserTenantRoles)
	token := generateToken(TokenData{UserId: refreshUser.ID, Roles: roles})
	userSafeData := refreshUser.Safe()
	userSafeData["Token"] = token
	userSafeData["Tenants"] = models.GetUserTenants(refreshUser.ID)
	jsonHttpRespond(w, userSafeData, "", http.StatusOK)
}

func postAuthCheckToken(w http.ResponseWriter, r *http.Request, user AuthorizedUser, _ int) {
	u, _ := models.GetUserByID(user.User.ID)
	jsonHttpRespond(w, u.Safe(), "", http.StatusOK)
}
