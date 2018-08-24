package rest

import (
	"github.com/asaskevich/govalidator"
	"github.com/gorilla/mux"
	"github.com/mmirzaee/userist/models"
	"net/http"
	"strconv"
	log "github.com/sirupsen/logrus"
)

func getUserTenants(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	uid := mux.Vars(r)["id"]
	userID, errBadTenantID := strconv.Atoi(uid)
	if errBadTenantID != nil || !govalidator.IsNumeric(uid) {
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

	tenants := models.GetUserTenants(uint(userID))
	jsonHttpRespond(w, tenants, "", http.StatusOK)
}

func getTenants(w http.ResponseWriter, r *http.Request, user AuthorizedUser, _ int) {
	tenants := models.GetTenants()
	jsonHttpRespond(w, tenants, "", http.StatusOK)
}

func postTenants(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	hasCreateTenantPermission := hasPermission(&user, "ct", tenantID)

	if !hasCreateTenantPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil{
		log.Error(errParse.Error())
	}

	name := r.Form["name"][0]
	status := r.Form["status"][0]

	if !govalidator.IsNumeric(status) {
		jsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	s, _ := strconv.Atoi(status)

	tenant := models.CreateTenant(name, s)
	jsonHttpRespond(w, tenant, "", http.StatusOK)
}

func updateTenant(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	hasCreateTenantPermission := hasPermission(&user, "ut", tenantID)

	if !hasCreateTenantPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	tid := mux.Vars(r)["id"]
	updatingTenantID, errBadTenantID := strconv.Atoi(tid)
	if errBadTenantID != nil {
		jsonHttpRespond(w, nil, "tenant_id is invalid", http.StatusForbidden)
		return
	}

	errParse := r.ParseForm()
	if errParse != nil{
		log.Error(errParse.Error())
	}

	name := r.Form["name"][0]
	status := r.Form["status"][0]

	if !govalidator.IsNumeric(status) {
		jsonHttpRespond(w, nil, "status is not valid", http.StatusBadRequest)
		return
	}

	s, _ := strconv.Atoi(status)

	models.UpdateTenant(uint(updatingTenantID), &models.Tenant{
		Name:   name,
		Status: s,
	})

	jsonHttpRespond(w, "tenant updated successfully", "", http.StatusOK)
}

func deleteTenant(w http.ResponseWriter, r *http.Request, user AuthorizedUser, tenantID int) {
	hasCreateTenantPermission := hasPermission(&user, "dt", tenantID)

	if !hasCreateTenantPermission {
		jsonHttpRespond(w, nil, "you dont have permission", http.StatusForbidden)
		return
	}

	tid := mux.Vars(r)["id"]
	deletingTenantID, errBadTenantID := strconv.Atoi(tid)
	if errBadTenantID != nil {
		jsonHttpRespond(w, nil, "tenant_id is invalid", http.StatusForbidden)
		return
	}

	models.DeleteTenant(uint(deletingTenantID))

	jsonHttpRespond(w, "tenant deleted successfully", "", http.StatusOK)
}
