package main

import (
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/mmirzaee/userist/models"
	"github.com/mmirzaee/userist/rest"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func init() {
	InitConfig()
	models.Init()
}

func main() {
	rest.Serve()
}

// initConfig reads in config file and ENV variables if set.
func InitConfig() {

	viper.AddConfigPath(".")
	viper.SetConfigName("config")

	viper.SetDefault("http_server", map[string]interface{}{"port": 4110, "host": "127.0.0.1"})
	viper.SetDefault("jwt", map[string]interface{}{"secret": "DefaultUseristJWTsecRet!", "lifetime": 86400})
	viper.SetDefault("log", map[string]interface{}{"enable_http_requests_log": false, "enable_mysql_queries_log": false})

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.WithFields(log.Fields{
			"file": viper.ConfigFileUsed(),
		}).Info("CONFIG: Loaded")
	} else {
		log.Fatal("CONFIG: File Not Found!")
	}
}
