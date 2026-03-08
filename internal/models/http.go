package models

type HTTPResponse struct {
    StatusCode  int               `json:"status_code"`
    Headers     map[string]string `json:"headers"`
    Body        string            `json:"body,omitempty"`
    BodyHash    string            `json:"body_hash"`
    Title       string            `json:"title,omitempty"`
    Server      string            `json:"server,omitempty"`
    ContentType string            `json:"content_type,omitempty"`
}