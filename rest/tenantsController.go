package rest

import (
	"net/http"
	"github.com/mmirzaee/userist/models"
	"github.com/gorilla/mux"
	"github.com/asaskevich/govalidator"
	"strconv"
)

func GetUserTenants(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	uid, _ := mux.Vars(r)["id"]
	userID, errBadTenantID := strconv.Atoi(uid)
	if errBadTenantID != nil || !govalidator.IsNumeric(uid) {
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

	tenants := models.GetUserTenants(uint(userID))
	JsonHttpRespond(w, tenants, "", http.StatusOK)
}

func GetTenants(w http.ResponseWriter, r *http.Request, user AuthorizedUser, _ int) {
	tenants := models.GetTenants()
	JsonHttpRespond(w, tenants, "", http.StatusOK)
}

func PostTenants(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	hasCreateTenantPermission := HasPermission(&user, "ct", tenantID)

	if !hasCreateTenantPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	r.ParseForm()
	name := r.Form["name"][0]
	status := r.Form["status"][0]

	if !govalidator.IsNumeric(status) {
		JsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	s, _ := strconv.Atoi(status)

	tenant := models.CreateTenant(name, s)
	JsonHttpRespond(w, tenant, "", http.StatusOK)
}

func UpdateTenant(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	hasCreateTenantPermission := HasPermission(&user, "ut", tenantID)

	if !hasCreateTenantPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	tid, _ := mux.Vars(r)["id"]
	updatingTenantID, errBadTenantID := strconv.Atoi(tid)
	if errBadTenantID != nil {
		JsonHttpRespond(w, nil, "tenant_id is invalid", http.StatusForbidden)
		return
	}

	r.ParseForm()
	name := r.Form["name"][0]
	status := r.Form["status"][0]

	if !govalidator.IsNumeric(status) {
		JsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	s, _ := strconv.Atoi(status)

	models.UpdateTenant(uint(updatingTenantID), &models.Tenant{
		Name:   name,
		Status: s,
	})

	JsonHttpRespond(w, "tenant updated successfully", "", http.StatusOK)
}

func DeleteTenant(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	hasCreateTenantPermission := HasPermission(&user, "dt", tenantID)

	if !hasCreateTenantPermission {
		JsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	tid, _ := mux.Vars(r)["id"]
	deletingTenantID, errBadTenantID := strconv.Atoi(tid)
	if errBadTenantID != nil {
		JsonHttpRespond(w, nil, "tenant_id is invalid", http.StatusForbidden)
		return
	}

	models.DeleteTenant(uint(deletingTenantID))

	JsonHttpRespond(w, "tenant deleted successfully", "", http.StatusOK)
}
