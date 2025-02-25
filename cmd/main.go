package main

import (
	"VipNetRulesEngine/internal/server"
	"VipNetRulesEngine/internal/transport/handlers"
	"VipNetRulesEngine/pkg/logger"
	"log"

	"github.com/spf13/viper"
)

func init() {
	viper.AddConfigPath("configs")
	viper.SetConfigName("config")
	viper.ReadInConfig()
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Ошибка при чтении конфигурации: %v", err)
	}
}
func main() {
	logger := logger.GetLogger()
	handler := handlers.InitHandlers(logger)
	srv := new(server.Server)
	srv.Start(handler.InitRoutes())
}
