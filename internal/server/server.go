package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type Server struct {
	httpServer *http.Server
}

func (s *Server) Start(router *gin.Engine) error {
	s.httpServer = &http.Server{
		Addr:         viper.GetString("server.ip") + ":" + viper.GetString("server.port"),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return s.httpServer.ListenAndServe()
}
