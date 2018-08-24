package rest

import (
	"net/http"
	"github.com/mmirzaee/userist/models"
)

func GetRoles(w http.ResponseWriter, r *http.Request, _ AuthorizedUser, _ int) {
	JsonHttpRespond(w, models.Roles(), "", http.StatusOK)
}
