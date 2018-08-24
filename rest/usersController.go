package rest

import (
	"net/http"
	"github.com/asaskevich/govalidator"
	"strconv"
	"github.com/mmirzaee/userist/models"
	"fmt"
	"strings"
	"github.com/gorilla/mux"
)

func GetUsers(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	hasReadUsersPermission := HasPermission(&user, "rou", tenantID)

	if !hasReadUsersPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
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
			JsonHttpRespond(w, nil, "page parameter must be numeric", http.StatusBadRequest)
			return
		} else {
			pageNo, _ = strconv.Atoi(queryPage);
		}
	}

	if queryStatus != "" {
		if !govalidator.IsNumeric(queryStatus) {
			JsonHttpRespond(w, nil, "status parameter must be numeric", http.StatusBadRequest)
			return
		} else {
			status, _ = strconv.Atoi(queryStatus);
		}
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
		JsonHttpRespond(w, Users, "", http.StatusOK)
	} else {
		JsonHttpRespond(w, nil, "users not found", http.StatusNotFound)
	}
}

func PostUsers(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	hasCreateUserPermission := HasPermission(&user, "cu", tenantID)
	if !hasCreateUserPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	r.ParseForm()
	username := r.Form["username"][0]
	password := r.Form["password"][0]
	email := r.Form["email"][0]
	displayName := r.Form["display_name"][0]
	status := r.Form["status"][0]
	role := r.Form["role"][0]

	// Validation
	if username == "" || password == "" || email == "" || displayName == "" || status == "" {
		JsonHttpRespond(w, nil, "username, password, email and display_name are required", http.StatusBadRequest)
		return
	}

	if !govalidator.IsEmail(email) {
		JsonHttpRespond(w, nil, "email is not valid", http.StatusBadRequest)
		return
	}

	if !govalidator.IsNumeric(status) {
		JsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	s, _ := strconv.Atoi(status)
	hashedPassword, _ := HashPassword(password)

	userId, errCreateUser := models.CreateUser(&models.User{
		Username:    username,
		Password:    hashedPassword,
		Email:       email,
		DisplayName: displayName,
		Status:      s,
	})

	if errCreateUser != nil {
		JsonHttpRespond(w, nil, errCreateUser.Error(), http.StatusInternalServerError)
		return
	}

	userRole := "user"
	if role != "" {
		roles := models.Roles()
		roleExists := false;
		for _, r := range roles.Roles {
			if r.Name == role {
				roleExists = true;
			}
		}

		if roleExists {
			userRole = role
		}
	}
	models.AddOrUpdateTenantRole(userId, tenantID, userRole, "", "")

	for key, val := range r.Form {
		if strings.HasPrefix(key, "meta_") {
			models.AddOrUpdateUserMeta(userId, strings.TrimPrefix(key, "meta_"), val[0], false)
		} else if strings.HasPrefix(key, "umeta_") {
			models.AddOrUpdateUserMeta(userId, strings.TrimPrefix(key, "umeta_"), val[0], true)
		}
	}

	newUser, errGetUser := models.GetUserByID(userId)

	if errGetUser != nil {
		JsonHttpRespond(w, nil, errGetUser.Error(), http.StatusInternalServerError)
		return
	}

	JsonHttpRespond(w, newUser.Safe(), "", http.StatusOK)

}

func GetSingleUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	hasReadPermission := false
	if uint(userID) == user.User.ID {
		hasReadPermission = HasPermission(&user, "rsu", tenantID)
	} else {
		hasReadPermission = HasPermission(&user, "rou", tenantID)
	}

	if !hasReadPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	metaKey, _ := mux.Vars(r)["key"]

	metaValue, errGetUserMeta := models.GetUserMetaValue(uint(userID), metaKey, tenantID)

	if errGetUserMeta != nil {
		JsonHttpRespond(w, nil, errGetUserMeta.Error(), http.StatusNotFound)
		return
	}

	JsonHttpRespond(w, metaValue, "", http.StatusOK)
}

func UpdateSingleUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	hasUpdatePermission := false
	if uint(userID) == user.User.ID {
		hasUpdatePermission = HasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = HasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	r.ParseForm()
	metaKey, _ := mux.Vars(r)["key"]
	metaValue := r.Form["value"][0]

	if metaKey == "" {
		JsonHttpRespond(w, nil, "value is required", http.StatusBadRequest)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user with id: "+strconv.Itoa(userID)+" does not exist in tenant: "+strconv.Itoa(tenantID), http.StatusNotFound)
		return
	}

	models.AddOrUpdateUserMeta(uint(userID), metaKey, metaValue, false)

	JsonHttpRespond(w, "meta \""+metaKey+"\" has been updated", "", http.StatusOK)
}

func UpdateSingleUniqueUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	hasUpdatePermission := false
	if uint(userID) == user.User.ID {
		hasUpdatePermission = HasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = HasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	r.ParseForm()
	metaKey, _ := mux.Vars(r)["key"]
	metaValue := r.Form["value"][0]

	if metaKey == "" {
		JsonHttpRespond(w, nil, "value is required", http.StatusBadRequest)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user with id: "+strconv.Itoa(userID)+" does not exist in tenant: "+strconv.Itoa(tenantID), http.StatusNotFound)
		return
	}

	if errUpdateUserMeta := models.AddOrUpdateUserMeta(uint(userID), metaKey, metaValue, true); errUpdateUserMeta != nil {
		JsonHttpRespond(w, nil, errUpdateUserMeta.Error(), http.StatusInternalServerError)
		return;
	}

	JsonHttpRespond(w, "meta \""+metaKey+"\" has been updated", "", http.StatusOK)
}

func UpdateUserPermissions(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {

	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	hasUpdatePermission := HasPermission(&user, "uou", tenantID) && HasPermission(&user, "uusd", tenantID)

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	r.ParseForm()
	include, includeExists := r.Form["include"]
	exclude, excludeExists := r.Form["exclude"]
	newRole, newRoleExists := r.Form["role"]

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user with id: "+strconv.Itoa(userID)+" does not exist in tenant: "+strconv.Itoa(tenantID), http.StatusNotFound)
		return
	}

	updatingUser, _ := models.GetUserByID(uint(userID))

	userRole := "user"
	for _, role := range updatingUser.UserTenantRoles {
		if (int(role.TenantID) == tenantID) {
			userRole = role.Role
			break
		}
	}

	if newRoleExists {
		roles := models.Roles()
		roleExists := false;
		for _, r := range roles.Roles {
			if r.Name == newRole[0] {
				roleExists = true;
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

	JsonHttpRespond(w, "user permission has been updated", "", http.StatusOK)
}

func GetSingleUser(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil || !govalidator.IsNumeric(uid) {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	hasReadPermission := false

	if uint(userID) == user.User.ID {
		hasReadPermission = HasPermission(&user, "rsu", tenantID)
	} else {
		hasReadPermission = HasPermission(&user, "rou", tenantID)
	}

	if !hasReadPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	queriedUser, err := models.GetUserByID(uint(userID))
	if err != nil {
		JsonHttpRespond(w, nil, "user not found with id:"+strconv.Itoa(userID), http.StatusNotFound)
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
		JsonHttpRespond(w, queriedUser.Safe(), "", http.StatusOK)
	} else {
		JsonHttpRespond(w, nil, "user not found in tenant:"+strconv.Itoa(tenantID), http.StatusNotFound)
	}
}

func PostUpdateUser(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	r.ParseForm()

	hasUpdatePermission := false
	if uint(userID) == user.User.ID {
		hasUpdatePermission = HasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = HasPermission(&user, "uou", tenantID)
	}

	password := r.Form["password"][0]
	email := r.Form["email"][0]
	displayName := r.Form["display_name"][0]
	status := r.Form["status"][0]
	role := r.Form["role"][0]

	updatesMetaData := false
	for key, _ := range r.Form {
		if strings.HasPrefix(key, "meta_") || strings.HasPrefix(key, "umeta_") {
			updatesMetaData = true
			break
		}
	}

	if updatesMetaData || role != "" || status != "" {
		hasUpdatePermission = hasUpdatePermission && HasPermission(&user, "uusd", tenantID)
	}

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	if email != "" && !govalidator.IsEmail(email) {
		JsonHttpRespond(w, nil, "email is not valid", http.StatusBadRequest)
		return
	}

	if status != "" && !govalidator.IsNumeric(status) {
		JsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	finalPassword := ""
	if password != "" {
		hashedPassword, _ := HashPassword(password)
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
		roleExists := false;
		for _, r := range roles.Roles {
			if r.Name == role {
				roleExists = true;
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
			models.AddOrUpdateUserMeta(uint(userID), strings.TrimPrefix(key, "meta_"), val[0], false)
		} else if strings.HasPrefix(key, "umeta_") {
			models.AddOrUpdateUserMeta(uint(userID), strings.TrimPrefix(key, "umeta_"), val[0], true)
		}
	}

	newUser, errGetUser := models.GetUserByID(uint(userID))
	if errGetUser != nil {
		JsonHttpRespond(w, nil, errGetUser.Error(), http.StatusInternalServerError)
		return
	}

	JsonHttpRespond(w, newUser.Safe(), "", http.StatusOK)
}

func DeleteUser(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	r.ParseForm()

	hasUpdatePermission := HasPermission(&user, "uusd", tenantID)

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	models.DeleteUser(uint(userID))

	JsonHttpRespond(w, "user deleted", "", http.StatusOK)
}

func DeleteUserMeta(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	r.ParseForm()
	metaKey, _ := mux.Vars(r)["key"]

	hasUpdatePermission := false
	if uint(userID) == user.User.ID {
		hasUpdatePermission = HasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = HasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	models.DeleteUserMeta(uint(userID), metaKey)

	JsonHttpRespond(w, "user meta deleted", "", http.StatusOK)
}

func DeleteUserTenantRole(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	// Check Permission
	uid, _ := mux.Vars(r)["id"]
	userID, errBadUserID := strconv.Atoi(uid)
	if errBadUserID != nil {
		JsonHttpRespond(w, nil, "user_id is invalid", http.StatusForbidden)
		return
	}

	r.ParseForm()

	hasUpdatePermission := false
	if uint(userID) == user.User.ID {
		hasUpdatePermission = HasPermission(&user, "usu", tenantID)
	} else {
		hasUpdatePermission = HasPermission(&user, "uou", tenantID)
	}

	if !hasUpdatePermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	if !models.UserExists(uint(userID), tenantID) {
		JsonHttpRespond(w, nil, "user not found", http.StatusNotFound)
		return
	}

	models.DeleteUserTenantRole(uint(userID), uint(tenantID))

	JsonHttpRespond(w, "user permissions deleted", "", http.StatusOK)
}
