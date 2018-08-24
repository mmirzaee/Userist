package models

import (
	"github.com/jinzhu/gorm"
	"time"
)

/*
GORM (table) types
*/

// User - user structure
type User struct {
	gorm.Model
	Username        string `gorm:"type:varchar(32);unique_index;not null"`
	Password        string `gorm:"type:varchar(64);not null"`
	Email           string `gorm:"type:varchar(32);unique"`
	DisplayName     string `gorm:"type:varchar(32)"`
	Status          int    `gorm:"type:int(3);not null;index;default:1"`
	UserMetas       []UserMeta
	UserTenantRoles []UserTenantRole
}

// Safe - return user data in a safe way
func (user *User) Safe() map[string]interface{} {
	roles := make(map[int]string)

	for _, r := range user.UserTenantRoles {
		roles[int(r.TenantID)] = r.Role
	}

	return map[string]interface{}{
		"User": map[string]interface{}{
			"ID":          user.ID,
			"DisplayName": user.DisplayName,
			"Username":    user.Username,
			"Status":      user.Status,
			"CreatedAt":   user.CreatedAt,
		},
		"Metas":       FormatUserMeta(user.UserMetas),
		"Permissions": GetUserTenantsPermissions(user.UserTenantRoles),
		"Roles":       roles,
	}
}

// UserMeta - user meta structure
type UserMeta struct {
	ID        uint   `gorm:"primary_key"`
	UserID    uint   `gorm:"index;not null"`
	MetaKey   string `gorm:"type:varchar(255);not null;index"`
	MetaValue string `gorm:"type:longtext;not null"`
}

// Tenant - tenant structure
type Tenant struct {
	ID     uint   `gorm:"primary_key"`
	Name   string `gorm:"type:varchar(32);not null"`
	Status int    `gorm:"type:int(1);not null;index"`
}

// UserTenantRole - user tenant role structure
type UserTenantRole struct {
	gorm.Model
	UserID              uint   `gorm:"index;not null"`
	TenantID            uint   `gorm:"index;not null"`
	Role                string `gorm:"type:varchar(32);not null;index"`
	IncludedPermissions string `gorm:"type:varchar(512)"`
	ExcludedPermissions string `gorm:"type:varchar(512)"`
}

/*
Internal types
*/

// Permission - permission structure
type Permission struct {
	Id    string
	Title string
}

// Role - role structure
type Role struct {
	Name        string
	Permissions []string
}

// RolesResponse - response type of a role
type RolesResponse struct {
	Roles       []Role
	Permissions []Permission
}

// UsersFilterFields - fields for filtering a user
type UsersFilterFields struct {
	Username    string
	Email       string
	DisplayName string
	Role        string
	MetaKey     string
	MetaValue   string
	Page        int
	Status      int
	OrderBy     string
	Order       string
}

// UserWithRole - user data + role data
type UserWithRole struct {
	ID          uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Username    string
	Email       string
	DisplayName string
	Status      int
	Role        string
}
