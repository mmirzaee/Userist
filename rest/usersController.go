package rest

import (
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/gorilla/mux"
	"github.com/mmirzaee/userist/models"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
)

func getUsers(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	hasReadUsersPermission := hasPermission(&user, "rou", tenantID)

	if !hasReadUsersPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	queryPage := r.URL.Query().Get("page")
	pageNo := 1

	queryRole := r.URL.Query().Get("role")
	queryUsername := r.URL.Query().Get("username")
	queryEmail := r.URL.Query().Get("email")
	queryDisplayName := r.URL.Query().Get("display_name")
	queryStatus := r.URL.Query().Get("status")
	status := -1
	queryOrderby := r.URL.Query().Get("orderby")
	queryOrder := r.URL.Query().Get("order")
	queryMetaKey := r.URL.Query().Get("meta_key")
	queryMetaValue := r.URL.Query().Get("meta_value")

	if queryPage != "" {
		if !govalidator.IsNumeric(queryPage) {
			jsonHttpRespond(w, nil, "page parameter must be numeric", http.StatusBadRequest)
			return
		}

		pageNo, _ = strconv.Atoi(queryPage)

	}

	if queryStatus != "" {
		if !govalidator.IsNumeric(queryStatus) {
			jsonHttpRespond(w, nil, "status parameter must be numeric", http.StatusBadRequest)
			return
		}

		status, _ = strconv.Atoi(queryStatus)

	}

	fmt.Println(tenantID)
	Users := models.GetUsers(models.UsersFilterFields{
		DisplayName: queryDisplayName,
		Role:        queryRole,
		Status:      status,
		Email:       queryEmail,
		MetaKey:     queryMetaKey,
		MetaValue:   queryMetaValue,
		Username:    queryUsername,
		OrderBy:     queryOrderby,
		Order:       queryOrder,
		Page:        pageNo,
	}, tenantID)

	if len(Users) > 0 {
		jsonHttpRespond(w, Users, "", http.StatusOK)
	} else {
		jsonHttpRespond(w, nil, "users not found", http.StatusNotFound)
	}
}

func postUsers(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	hasCreateUserPermission := hasPermission(&user, "cu", tenantID)
	if !hasCreateUserPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	username := r.Form["username"][0]
	password := r.Form["password"][0]
	email := r.Form["email"][0]
	displayName := r.Form["display_name"][0]
	status := r.Form["status"][0]
	role := r.Form["role"][0]

	// Validation
	if username == "" || password == "" || email == "" || displayName == "" || status == "" {
		jsonHttpRespond(w, nil, "username, password, email and display_name are required", http.StatusBadRequest)
		return
	}

	if !govalidator.IsEmail(email) {
		jsonHttpRespond(w, nil, "email is not valid", http.StatusBadRequest)
		return
	}

	if !govalidator.IsNumeric(status) {
		jsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	s, _ := strconv.Atoi(status)
	hashedPassword, _ := hashPassword(password)

	userId, errCreateUser := models.CreateUser(&models.User{
		Username:    username,
		Password:    hashedPassword,
		Email:       email,
		DisplayName: displayName,
		Status:      s,
	})

	if errCreateUser != nil {
		jsonHttpRespond(w, nil, errCreateUser.Error(), http.StatusInternalServerError)
		return
	}

	userRole := "user"
	if role != "" {
		roles := models.Roles()
		roleExists := false
		for _, r := range roles.Roles {
			if r.Name == role {
				roleExists = true
			}
		}

		if roleExists {
			userRole = role
		}
	}
	models.AddOrUpdateTenantRole(userId, tenantID, userRole, "", "")

	for key, val := range r.Form {
		if strings.HasPrefix(key, "meta_") {
			errUserMeta := models.AddOrUpdateUserMeta(userId, strings.TrimPrefix(key, "meta_"), val[0], false)
			if errUserMeta != nil {
				log.Error(errUserMeta.Error())
			}
		} else if strings.HasPrefix(key, "umeta_") {
			errUserMeta := models.AddOrUpdateUserMeta(userId, strings.TrimPrefix(key, "umeta_"), val[0], true)
			if errUserMeta != nil {
				log.Error(errUserMeta.Error())
			}
		}
	}

	newUser, errGetUser := models.GetUserByID(userId)

	if errGetUser != nil {
		jsonHttpRespond(w, nil, errGetUser.Error(), http.StatusInternalServerError)
		return
	}

	jsonHttpRespond(w, newUser.Safe(), "", http.StatusOK)

}

func getSingleUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	var hasReadPermission bool
	if uint(userID) == user.User.ID {
		hasReadPermission = hasPermission(&user, "rsu", tenantID)
	} else {
		hasReadPermission = hasPermission(&user, "rou", tenantID)
	}

	if !hasReadPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	metaKey := mux.Vars(r)["key"]

	metaValue, errGetUserMeta := models.GetUserMetaValue(uint(userID), metaKey, tenantID)

	if errGetUserMeta != nil {
		jsonHttpRespond(w, nil, errGetUserMeta.Error(), http.StatusNotFound)
		return
	}

	jsonHttpRespond(w, metaValue, "", http.StatusOK)
}

func updateSingleUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	var hasUpdatePermission bool
	if uint(userID) == user.User.ID {
		hasUpdatePermission = hasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = hasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	metaKey := mux.Vars(r)["key"]
	metaValue := r.Form["value"][0]

	if metaKey == "" {
		jsonHttpRespond(w, nil, "value is required", http.StatusBadRequest)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user with id: "+strconv.Itoa(userID)+" does not exist in tenant: "+strconv.Itoa(tenantID), http.StatusNotFound)
		return
	}

	errUserMeta := models.AddOrUpdateUserMeta(uint(userID), metaKey, metaValue, false)
	if errUserMeta != nil {
		log.Error(errUserMeta.Error())
	}

	jsonHttpRespond(w, "meta \""+metaKey+"\" has been updated", "", http.StatusOK)
}

func updateSingleUniqueUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	var hasUpdatePermission bool
	if uint(userID) == user.User.ID {
		hasUpdatePermission = hasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = hasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	metaKey := mux.Vars(r)["key"]
	metaValue := r.Form["value"][0]

	if metaKey == "" {
		jsonHttpRespond(w, nil, "value is required", http.StatusBadRequest)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user with id: "+strconv.Itoa(userID)+" does not exist in tenant: "+strconv.Itoa(tenantID), http.StatusNotFound)
		return
	}

	if errUpdateUserMeta := models.AddOrUpdateUserMeta(uint(userID), metaKey, metaValue, true); errUpdateUserMeta != nil {
		jsonHttpRespond(w, nil, errUpdateUserMeta.Error(), http.StatusInternalServerError)
		return
	}

	jsonHttpRespond(w, "meta \""+metaKey+"\" has been updated", "", http.StatusOK)
}

func updateUserPermissions(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	hasUpdatePermission := hasPermission(&user, "uou", tenantID) && hasPermission(&user, "uusd", tenantID)

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	include, includeExists := r.Form["include"]
	exclude, excludeExists := r.Form["exclude"]
	newRole, newRoleExists := r.Form["role"]

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user with id: "+strconv.Itoa(userID)+" does not exist in tenant: "+strconv.Itoa(tenantID), http.StatusNotFound)
		return
	}

	updatingUser, _ := models.GetUserByID(uint(userID))

	userRole := "user"
	for _, role := range updatingUser.UserTenantRoles {
		if int(role.TenantID) == tenantID {
			userRole = role.Role
			break
		}
	}

	if newRoleExists {
		roles := models.Roles()
		roleExists := false
		for _, r := range roles.Roles {
			if r.Name == newRole[0] {
				roleExists = true
			}
		}

		if roleExists {
			userRole = newRole[0]
		}
	}

	finalInclude := ""
	finalExclude := ""

	if includeExists {
		finalInclude = include[0]
	}
	if excludeExists {
		finalExclude = exclude[0]
	}

	models.AddOrUpdateTenantRole(uint(userID), tenantID, userRole, finalInclude, finalExclude)

	jsonHttpRespond(w, "user permission has been updated", "", http.StatusOK)
}

func getSingleUser(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	var hasReadPermission bool

	if uint(userID) == user.User.ID {
		hasReadPermission = hasPermission(&user, "rsu", tenantID)
	} else {
		hasReadPermission = hasPermission(&user, "rou", tenantID)
	}

	if !hasReadPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	queriedUser, err := models.GetUserByID(uint(userID))
	if err != nil {
		jsonHttpRespond(w, nil, "user not found with id:"+strconv.Itoa(userID), http.StatusNotFound)
		return
	}

	isInCurrentTenant := false
	for _, tenantRole := range queriedUser.UserTenantRoles {
		if tenantRole.TenantID == uint(tenantID) {
			isInCurrentTenant = true
			break
		}
	}

	if isInCurrentTenant {
		jsonHttpRespond(w, queriedUser.Safe(), "", http.StatusOK)
	} else {
		jsonHttpRespond(w, nil, "user not found in tenant:"+strconv.Itoa(tenantID), http.StatusNotFound)
	}
}

func postUpdateUser(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	var hasUpdatePermission bool
	if uint(userID) == user.User.ID {
		hasUpdatePermission = hasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = hasPermission(&user, "uou", tenantID)
	}

	password := r.Form["password"][0]
	email := r.Form["email"][0]
	displayName := r.Form["display_name"][0]
	status := r.Form["status"][0]
	role := r.Form["role"][0]

	updatesMetaData := false
	for key := range r.Form {
		if strings.HasPrefix(key, "meta_") || strings.HasPrefix(key, "umeta_") {
			updatesMetaData = true
			break
		}
	}

	if updatesMetaData || role != "" || status != "" {
		hasUpdatePermission = hasUpdatePermission && hasPermission(&user, "uusd", tenantID)
	}

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	if email != "" && !govalidator.IsEmail(email) {
		jsonHttpRespond(w, nil, "email is not valid", http.StatusBadRequest)
		return
	}

	if status != "" && !govalidator.IsNumeric(status) {
		jsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	finalPassword := ""
	if password != "" {
		hashedPassword, _ := hashPassword(password)
		finalPassword = hashedPassword
	}

	finalStatus := -1
	if status != "" {
		s, _ := strconv.Atoi(status)
		finalStatus = s
	}

	models.UpdateUser(uint(userID), &models.User{
		Password:    finalPassword,
		Email:       email,
		DisplayName: displayName,
		Status:      finalStatus,
	})

	userRole := ""
	if role != "" {
		roles := models.Roles()
		roleExists := false
		for _, r := range roles.Roles {
			if r.Name == role {
				roleExists = true
			}
		}

		if roleExists {
			userRole = role
		}
	}

	if userRole != "" {
		models.AddOrUpdateTenantRole(uint(userID), tenantID, userRole, "", "")
	}

	for key, val := range r.Form {
		if strings.HasPrefix(key, "meta_") {
			errUserMeta := models.AddOrUpdateUserMeta(uint(userID), strings.TrimPrefix(key, "meta_"), val[0], false)
			if errUserMeta != nil {
				log.Error(errUserMeta.Error())
			}
		} else if strings.HasPrefix(key, "umeta_") {
			errUserMeta := models.AddOrUpdateUserMeta(uint(userID), strings.TrimPrefix(key, "umeta_"), val[0], true)
			if errUserMeta != nil {
				log.Error(errUserMeta.Error())
			}
		}
	}

	newUser, errGetUser := models.GetUserByID(uint(userID))
	if errGetUser != nil {
		jsonHttpRespond(w, nil, errGetUser.Error(), http.StatusInternalServerError)
		return
	}

	jsonHttpRespond(w, newUser.Safe(), "", http.StatusOK)
}

func deleteUser(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	hasUpdatePermission := hasPermission(&user, "uusd", tenantID)

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	models.DeleteUser(uint(userID))

	jsonHttpRespond(w, "user deleted", "", http.StatusOK)
}

func deleteUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	metaKey := mux.Vars(r)["key"]

	var hasUpdatePermission bool
	if uint(userID) == user.User.ID {
		hasUpdatePermission = hasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = hasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	models.DeleteUserMeta(uint(userID), metaKey)

	jsonHttpRespond(w, "user meta deleted", "", http.StatusOK)
}

func deleteUserTenantRole(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		jsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil {
		log.Error(errParse.Error())
	}

	var hasUpdatePermission bool
	if uint(userID) == user.User.ID {
		hasUpdatePermission = hasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = hasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		jsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	models.DeleteUserTenantRole(uint(userID), uint(tenantID))

	jsonHttpRespond(w, "user permissions deleted", "", http.StatusOK)
}
