package handlers

import (
	"html/template"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) InitRoutes() *gin.Engine {
	var tpl = template.Must(template.ParseFiles("index.html"))
	router := gin.Default()
	router.SetHTMLTemplate(tpl)
	router.GET("/", h.GetPageHandler)
	router.POST("/upload", h.UploadFileHandler)
	return router
}
