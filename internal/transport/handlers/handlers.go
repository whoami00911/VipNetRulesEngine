package handlers

import (
	"VipNetRulesEngine/pkg/logger"
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	logger *logger.Logger
}

func InitHandlers(logger *logger.Logger) *Handlers {
	return &Handlers{
		logger: logger,
	}
}

func (h *Handlers) GetPageHandler(c *gin.Context) {
	c.HTML(200, "index.html", nil)
}

func (h *Handlers) UploadFileHandler(c *gin.Context) {
	headerFile, err := c.FormFile("uploadFile")
	if err != nil {
		h.logger.Error(fmt.Sprintf("Error getting head of File: %s", err))
		return
	}

	file, err := headerFile.Open()
	if err != nil {
		h.logger.Error(fmt.Sprintf("Error open File: %s", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	layers := make(map[string][]string)
	var currentLayer string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "//") {
			currentLayer = strings.TrimSpace(strings.TrimPrefix(line, "//"))
			fmt.Println(currentLayer)

			layers[currentLayer] = []string{}
		} else {
			// Если уже найден слой, добавляем строку в его срез
			if currentLayer == "Danger Connection" {
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert tcp $HOME_NET any -> %s any (msg:"Danger Connection - Malicious IP"; classtype:web-application-attack;)`, line))
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert udp $HOME_NET any -> %s any (msg:"Danger Connection - Malicious IP"; classtype:web-application-attack;)`, line))
			} else if currentLayer == "Danger Dns Request" {
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Danger Dns Request - %s"; uricontent:"%s"; nocase; classtype:web-application-attack;)`, line, line))
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Danger Dns Request - %s"; uricontent:"%s"; nocase; classtype:web-application-attack;)`, line, line))
			} else if currentLayer == "Malware File Detected sha256" {
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware File Detected - SHA256 Hash Match"; protected_content:"%s"; hash:sha256; offset:0; length:4; classtype:trojan-activity;)`, line))
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware File Detected - SHA256 Hash Match"; protected_content:"%s"; hash:sha256; offset:0; length:4; classtype:trojan-activity;)`, line))
			} else if currentLayer == "Malware Download" {
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Malware Download - %s"; content:"%s"; nocase; classtype:trojan-activity;)`, line, line))
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"Malware Download - %s"; content:"%s"; nocase; classtype:trojan-activity;)`, line, line))
			} else if currentLayer == "Malware File Detected md5" {
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware File Detected - md5 Hash Match"; protected_content:"%s"; hash:md5; length:4; classtype:trojan-activity;)`, line))
				layers[currentLayer] = append(layers[currentLayer], fmt.Sprintf(`alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware File Detected - md5 Hash Match"; protected_content:"%s"; hash:md5; length:4; classtype:trojan-activity;)`, line))
			} else {
				h.logger.Error("не грузить хуйню")
			}
		}
	}
	outputFile, err := os.Create("output.rules")
	if err != nil {
		h.logger.Error(fmt.Sprintf("Error open File: %s", err))
		return
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)

	for _, content := range layers {
		for _, line := range content {
			if _, err := writer.WriteString(line + "\n"); err != nil {
				h.logger.Error(fmt.Sprintf("Error writing to file: %s", err))
				return
			}
		}

		if _, err := writer.WriteString("\n"); err != nil {
			h.logger.Error(fmt.Sprintf("Error writing to file: %s", err))
			return
		}
	}

	if err := writer.Flush(); err != nil {
		h.logger.Error(fmt.Sprintf("Error cleaning buffer: %s", err))
		return
	}

	c.FileAttachment(outputFile.Name(), outputFile.Name())

	if err := os.Remove(outputFile.Name()); err != nil {
		h.logger.Error(fmt.Sprintf("Cant delete file: %s", err))
	}
}
