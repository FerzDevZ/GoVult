package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type TelegramPayload struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
	Parse  string `json:"parse_mode"`
}

func SendTelegramNotification(token, chatID, target string, findings []Result) error {
	if token == "" || chatID == "" {
		return nil // Skip if not configured
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	// Format Message
	msg := fmt.Sprintf("🚀 *GoVult Scan Completed*\n\n")
	msg += fmt.Sprintf("🎯 *Target:* %s\n", target)
	msg += fmt.Sprintf("📊 *Total Findings:* %d\n", len(findings))

	if len(findings) > 0 {
		msg += "\n*Critical Findings:*\n"
		for i, f := range findings {
			if i >= 5 {
				msg += "...and more."
				break
			}
			msg += fmt.Sprintf("• [%s] %s\n", f.Severity, f.TemplateID)
		}
	}

	payload := TelegramPayload{
		ChatID: chatID,
		Text:   msg,
		Parse:  "Markdown",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram api error: status %d", resp.StatusCode)
	}

	return nil
}
