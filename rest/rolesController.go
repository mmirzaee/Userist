package rest

import (
	"github.com/mmirzaee/userist/models"
	"net/http"
)

func getRoles(w http.ResponseWriter, r *http.Request, _ AuthorizedUser, _ int) {
	jsonHttpRespond(w, models.Roles(), "", http.StatusOK)
}
