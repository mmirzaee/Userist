package models

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/jinzhu/gorm"
	"strings"
	"github.com/mitchellh/mapstructure"
	"fmt"
	"github.com/mmirzaee/userist/helper"
	"errors"
	"strconv"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB

func Init() {
	mysqlConfig := viper.GetStringMap("mysql")
	logConfig := viper.GetStringMap("log")

	connection, err := gorm.Open("mysql", mysqlConfig["username"].(string)+":"+mysqlConfig["password"].(string)+"@tcp("+mysqlConfig["host"].(string)+":"+mysqlConfig["port"].(string)+")/"+mysqlConfig["database"].(string)+"?charset=utf8&parseTime=True&loc=Local")
	db = connection

	if err != nil {
		log.Fatal(err)
	}

	if logConfig["enable_mysql_queries_log"] == true {
		db.LogMode(true)
	}

	db.AutoMigrate(&User{}, &UserMeta{}, &Tenant{}, &UserTenantRole{})

	// Seed admin user if there is non
	if err := db.First(&User{}).Error; err != nil {

		adminDefaultsConfig := viper.GetStringMap("admin_defaults")
		baseTenantDefaultsConfig := viper.GetStringMap("base_tenant_defaults")

		var newTenant = Tenant{
			Name:   baseTenantDefaultsConfig["name"].(string),
			Status: 1,
		}

		if err := db.Create(&newTenant).Error; err != nil {
			log.Fatal("Error creating initial tenant")
		}

		bytes, _ := bcrypt.GenerateFromPassword([]byte(adminDefaultsConfig["password"].(string)), 14)

		var newUser = User{
			Username:    adminDefaultsConfig["username"].(string),
			Password:    string(bytes),
			Email:       adminDefaultsConfig["email"].(string),
			DisplayName: adminDefaultsConfig["display_name"].(string),
			Status:      1,
		}

		if err := db.Create(&newUser).Error; err != nil {
			log.Fatal("Error creating admin user")
		}

		AddOrUpdateTenantRole(newUser.ID, int(newTenant.ID), "admin", "", "")
	}
}

func Roles() RolesResponse {
	var perms []Permission

	// Add default permissions
	perms = append(perms, Permission{Id: "rsu", Title: "read self user"})
	perms = append(perms, Permission{Id: "rou", Title: "read other user"})
	perms = append(perms, Permission{Id: "dou", Title: "delete other user"})
	perms = append(perms, Permission{Id: "usu", Title: "update self user"})
	perms = append(perms, Permission{Id: "uou", Title: "update other user"})
	perms = append(perms, Permission{Id: "cu", Title: "create user"})
	perms = append(perms, Permission{Id: "rusd", Title: "read users sensetive data"})
	perms = append(perms, Permission{Id: "uusd", Title: "update users sensetive data"})
	perms = append(perms, Permission{Id: "ct", Title: "create tenant"})
	perms = append(perms, Permission{Id: "ut", Title: "update tenant"})
	perms = append(perms, Permission{Id: "dt", Title: "delete tenant"})

	if viper.IsSet("permissions") {
		permissionsConfig := viper.Get("permissions").([]interface{})
		for _, val := range permissionsConfig {
			perm := Permission{}
			err := mapstructure.Decode(val, &perm)
			if err != nil {
				log.Error(val)
			}
			perms = append(perms, perm)
		}
	}

	var allPerms []string
	for _, val := range perms {
		allPerms = append(allPerms, val.Id)
	}

	var roles []Role

	// Add base roles
	roles = append(roles, Role{Name: "user", Permissions: []string{"rsu", "usu"}})
	roles = append(roles, Role{Name: "admin", Permissions: allPerms})

	if viper.IsSet("roles") {
		rolesConfig := viper.Get("roles").([]interface{})
		for _, val := range rolesConfig {
			r := val.(map[interface{}]interface{});
			inherits := r["inherits"].([]interface{})
			var rolePerms = []string{}
			for _, parent := range inherits {
				for _, val2 := range rolesConfig {
					r2 := val2.(map[interface{}]interface{});
					if r2["name"] == parent.(string) {
						for _, permissions := range r2["permissions"].([]interface{}) {
							rolePerms = append(rolePerms, permissions.(string))
						}
					}
				}
			}

			for _, selfPerm := range r["permissions"].([]interface{}) {
				rolePerms = append(rolePerms, selfPerm.(string))
			}

			helper.RemoveDuplicates(&rolePerms)

			role := Role{Name: r["name"].(string), Permissions: rolePerms}

			roles = append(roles, role)
		}
	}
	return RolesResponse{Permissions: perms, Roles: roles}
}

func GetUserByUsername(username string) (*User, error) {
	var user User
	if err := db.Preload("UserMetas").Preload("UserTenantRoles").Where(User{Username: username}).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByID(id uint) (*User, error) {
	var user User
	if err := db.Preload("UserMetas").Preload("UserTenantRoles").First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserTenantsPermissions(roles []UserTenantRole) map[int][]string {
	result := make(map[int][]string)
	r := Roles()

	for _, tenantRole := range roles {
		for _, role := range r.Roles {

			if tenantRole.Role == role.Name {
				if tenantRole.ExcludedPermissions != "" {
					excludedPermissions := strings.Split(tenantRole.ExcludedPermissions, ",")
					for _, selectedPerm := range role.Permissions {
						isPermExcluded := false
						for _, excludedPerm := range excludedPermissions {
							if selectedPerm == excludedPerm {
								isPermExcluded = true
							}
						}
						if !isPermExcluded {
							result[int(tenantRole.TenantID)] = append(result[int(tenantRole.ID)], selectedPerm)
						}
					}
				} else {
					result[int(tenantRole.TenantID)] = role.Permissions
				}

				if tenantRole.IncludedPermissions != "" {
					includedPermissions := strings.Split(tenantRole.IncludedPermissions, ",")
					for _, includedPerm := range includedPermissions {
						permAlreadyIncluded := false;
						for _, selectedPerm := range result[int(tenantRole.ID)] {
							if selectedPerm == includedPerm {
								permAlreadyIncluded = true;
							}
						}
						if (!permAlreadyIncluded) {
							result[int(tenantRole.TenantID)] = append(result[int(tenantRole.ID)], includedPerm)
						}
					}
				}
			}
		}
	}
	return result;
}

func GetUserTenants(userID uint) map[uint]string {
	var userTenantRoles []UserTenantRole
	var tenantIds []uint
	var tenants []Tenant

	db.Where(&UserTenantRole{UserID: userID}).Select("tenant_id").Find(&userTenantRoles)

	for _, utr := range userTenantRoles {
		tenantIds = append(tenantIds, utr.TenantID)
	}

	db.Where("ID in (?)", tenantIds).Find(&tenants)

	tenantsFormatted := make(map[uint]string)
	for _, t := range tenants {
		tenantsFormatted[t.ID] = t.Name
	}

	return tenantsFormatted
}

func GetTenants() map[uint]string {
	var tenants []Tenant

	db.Find(&tenants)

	tenantsFormatted := make(map[uint]string)
	for _, t := range tenants {
		tenantsFormatted[t.ID] = t.Name
	}

	return tenantsFormatted
}

func CreateTenant(name string, status int) Tenant {
	var newTenant = Tenant{
		Name:   name,
		Status: status,
	}
	db.Create(&newTenant)

	return newTenant
}

func UpdateTenant(tenantID uint, updatedTenant *Tenant) {
	var tenant Tenant
	db.First(&tenant, tenantID)

	if updatedTenant.Status != -1 {
		tenant.Status = updatedTenant.Status
	}

	if updatedTenant.Name != "" {
		tenant.Name = updatedTenant.Name
	}

	db.Save(&tenant)
}

func DeleteTenant(tenantID uint) {
	db.Unscoped().Where("id = ?", tenantID).Delete(&Tenant{})
	db.Unscoped().Where("tenant_id = ?", tenantID).Delete(&UserTenantRole{})
}

func GetUsers(args UsersFilterFields, tenantID int) []UserWithRole {
	tx := db.Table("users").Select("users.id, COALESCE(display_name, '') as display_name, COALESCE(email, '') as email, username, users.created_at, users.updated_at, status, COALESCE(user_tenant_roles.role, '') as role")
	tx = tx.Joins("LEFT JOIN user_tenant_roles on user_tenant_roles.user_id=users.id")
	tx = tx.Where("tenant_id = ?", tenantID)

	if args.Role != "" {
		tx = tx.Where("role = ?", args.Role)
	}
	if args.Username != "" {
		tx = tx.Where("username LIKE ?", fmt.Sprint("%", args.Username, "%"))
	}
	if args.Email != "" {
		tx = tx.Where("email LIKE ?", fmt.Sprint("%", args.Email, "%"))
	}
	if args.Status != -1 {
		tx = tx.Where("status = ?", args.Status)
	}
	if args.DisplayName != "" {
		tx = tx.Where("display_name LIKE ?", fmt.Sprint("%", args.DisplayName, "%"))
	}
	if args.MetaKey != "" {
		tx = tx.Joins("LEFT JOIN user_meta ON users.id = user_meta.user_id")
		tx = tx.Where("meta_key = ? AND meta_value = ?", args.MetaKey, args.MetaValue)
	}

	tx = tx.Limit(20).Offset(uint64((args.Page - 1) * 20))

	rows, err := tx.Rows()

	if err != nil {
		log.Error(err)
		return []UserWithRole{}
	}

	var usersWithRole []UserWithRole
	for rows.Next() {

		var t UserWithRole
		err := rows.Scan(&t.ID, &t.DisplayName, &t.Email, &t.Username, &t.CreatedAt, &t.UpdatedAt, &t.Status, &t.Role)

		if err != nil {
			log.Warn(err)
		} else {
			usersWithRole = append(usersWithRole, t)
		}

	}

	return usersWithRole
}

func FormatUserMeta(userMeta []UserMeta) map[string]string {
	um := make(map[string]string)
	for _, u := range userMeta {
		um[u.MetaKey] = u.MetaValue;
	}
	return um
}

func CreateUser(user *User) (uint, error) {
	var newUser = User{
		Username:    user.Username,
		Password:    user.Password,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      user.Status,
	}
	if err := db.Create(&newUser).Error; err != nil {
		return 0, err
	}

	return newUser.ID, nil
}

func AddOrUpdateTenantRole(userID uint, tenantID int, role string, includedPermissions string, excludedPermissions string) {
	var isNewRecord int
	var t UserTenantRole

	db.Where(UserTenantRole{UserID: userID, TenantID: uint(tenantID)}).First(&t).Count(&isNewRecord)

	if isNewRecord > 0 {
		// Needs update
		t.Role = role
		t.IncludedPermissions = includedPermissions
		t.ExcludedPermissions = excludedPermissions
		db.Save(&t)
	} else {
		// Needs Insert
		t = UserTenantRole{
			UserID:              userID,
			TenantID:            uint(tenantID),
			Role:                role,
			IncludedPermissions: includedPermissions,
			ExcludedPermissions: excludedPermissions,
		}
		db.Create(&t)
	}
}

func AddOrUpdateUserMeta(userID uint, metaKey string, metaValue string, isUnique bool) error {
	var um UserMeta

	if isUnique {
		if err := db.Where("user_id != ?", userID).Where("meta_key = ?", metaKey).Where("meta_value = ?", metaValue).First(&um).Error; err == nil {
			return errors.New("unique meta (" + metaKey + ") with provided value already exists")
		}
	}

	if err := db.Where("user_id = ?", userID).Where("meta_key = ?", metaKey).First(&um).Error; err != nil {
		db.Create(&UserMeta{
			UserID:    userID,
			MetaKey:   metaKey,
			MetaValue: metaValue,
		})
		return nil
	}

	um.MetaKey = metaKey
	um.MetaValue = metaValue
	db.Save(&um)
	return nil
}

func UserExists(userId uint, tenantId int) bool {
	if err := db.Where(&UserTenantRole{UserID: userId, TenantID: uint(tenantId)}).First(&UserTenantRole{}).Error; err != nil {
		return false
	}

	return true
}

func GetUserMetaValue(userID uint, metaKey string, tenantID int) (string, error) {
	if !UserExists(userID, tenantID) {
		return "", errors.New("user with id: " + strconv.Itoa(int(userID)) + " does not exist in tenant: " + strconv.Itoa(tenantID))
	}

	var um UserMeta
	if err := db.Where(&UserMeta{UserID: userID, MetaKey: metaKey}).First(&um).Error; err != nil {
		return "", err
	}

	return um.MetaValue, nil
}

func UpdateUser(userID uint, updateUser *User) {
	var user User
	db.First(&user, userID)

	if updateUser.Status != -1 {
		user.Status = updateUser.Status
	}

	if updateUser.Password != "" {
		user.Password = updateUser.Password
	}

	if updateUser.Email != "" {
		user.Email = updateUser.Email
	}

	if updateUser.DisplayName != "" {
		user.DisplayName = updateUser.DisplayName
	}

	db.Save(&user)
}

func DeleteUser(userID uint) {
	db.Unscoped().Where("id = ?", userID).Delete(&User{})
	db.Unscoped().Where("user_id = ?", userID).Delete(&UserTenantRole{})
	db.Unscoped().Where("user_id = ?", userID).Delete(&UserMeta{})
}

func DeleteUserMeta(userID uint, metaKey string) {
	db.Unscoped().Where("user_id = ?", userID).Where("meta_key = ?", metaKey).Delete(&UserMeta{})
}

func DeleteUserTenantRole(userID uint, tenantID uint) {
	db.Unscoped().Where("user_id = ?", userID).Where("tenant_id = ?", tenantID).Delete(&UserTenantRole{})
}
