package api

import (
	"bytes"
	"encoding/json"
)

// envelope is the {success,msg,obj} wrapper every 3x-ui / still-ui API call returns.
type envelope struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// Status is the subset of GET /panel/api/server/status that the checks use.
type Status struct {
	Xray struct {
		State    string `json:"state"`
		ErrorMsg string `json:"errorMsg"`
		Version  string `json:"version"`
	} `json:"xray"`
	PanelVersion string `json:"panelVersion"`
	// UpstreamVersion is reported by still-ui only: the 3x-ui release it is based on.
	UpstreamVersion string `json:"upstreamVersion"`
}

// JSONDoc holds a JSON document that the panel sends either embedded (3x-ui
// 3.x: "settings": {...}) or as a string containing JSON (older panels).
type JSONDoc []byte

// UnmarshalJSON accepts both forms and keeps the inner document.
func (d *JSONDoc) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*d = JSONDoc(s)
		return nil
	}
	if string(b) == "null" {
		*d = nil
		return nil
	}
	*d = append((*d)[:0], b...)
	return nil
}

// MarshalJSON writes the document embedded.
func (d JSONDoc) MarshalJSON() ([]byte, error) {
	if len(bytes.TrimSpace(d)) == 0 {
		return []byte("null"), nil
	}
	return d, nil
}

// Inbound mirrors model.Inbound as returned by GET /panel/api/inbounds/list.
type Inbound struct {
	ID             int             `json:"id"`
	Remark         string          `json:"remark"`
	Enable         bool            `json:"enable"`
	Listen         string          `json:"listen"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       JSONDoc         `json:"settings"`
	StreamSettings JSONDoc         `json:"streamSettings"`
	Tag            string          `json:"tag"`
	NodeID         *int            `json:"nodeId"`
	ExpiryTime     int64           `json:"expiryTime"`
	Total          int64           `json:"total"`
	Up             int64           `json:"up"`
	Down           int64           `json:"down"`
	ClientStats    []ClientTraffic `json:"clientStats"`
}

// ClientTraffic mirrors xray.ClientTraffic (the per-client counters row).
type ClientTraffic struct {
	InboundID  int    `json:"inboundId"`
	Enable     bool   `json:"enable"`
	Email      string `json:"email"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	ExpiryTime int64  `json:"expiryTime"`
	Total      int64  `json:"total"`
}

// HostGroup mirrors entity.HostGroup from GET /panel/api/hosts/list (3x-ui 3.x "Hosts").
type HostGroup struct {
	GroupID      string `json:"groupId"`
	InboundIDs   []int  `json:"inboundIds"`
	Remark       string `json:"remark"`
	IsDisabled   bool   `json:"isDisabled"`
	Security     string `json:"security"`
	Fingerprint  string `json:"fingerprint"`
	MihomoX25519 bool   `json:"mihomoX25519"`
}

// Settings is the subset of POST /panel/api/setting/all used by the checks.
// The panel masks secret values in this response and reports has* flags instead.
type Settings struct {
	WebListen       string `json:"webListen"`
	WebDomain       string `json:"webDomain"`
	WebPort         int    `json:"webPort"`
	WebCertFile     string `json:"webCertFile"`
	WebKeyFile      string `json:"webKeyFile"`
	WebBasePath     string `json:"webBasePath"`
	SessionMaxAge   int    `json:"sessionMaxAge"`
	TgBotEnable     bool   `json:"tgBotEnable"`
	HasTgBotToken   bool   `json:"hasTgBotToken"`
	TwoFactorEnable bool   `json:"twoFactorEnable"`
	SubEnable       bool   `json:"subEnable"`
	SubListen       string `json:"subListen"`
	SubPort         int    `json:"subPort"`
	SubCertFile     string `json:"subCertFile"`
	SubKeyFile      string `json:"subKeyFile"`
	SubPath         string `json:"subPath"`
	SubURI          string `json:"subURI"`
	SubJSONEnable   bool   `json:"subJsonEnable"`
	SubJSONPath     string `json:"subJsonPath"`
	SubJSONURI      string `json:"subJsonURI"`
}

// Fail2banStatus mirrors GET /panel/api/server/fail2banStatus.
type Fail2banStatus struct {
	Enabled   bool `json:"enabled"`
	Installed bool `json:"installed"`
	Usable    bool `json:"usable"`
	Windows   bool `json:"windows"`
}
