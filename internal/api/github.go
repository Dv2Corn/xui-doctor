package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GitHubAPI is the endpoint used for the release lookup; tests override it.
var GitHubAPI = "https://api.github.com"

// LatestRelease returns the tag of the latest published release of owner/name
// with one unauthenticated GitHub API call.
func LatestRelease(ctx context.Context, repo string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubAPI+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "xui-doctor")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API: HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("GitHub API: no tag in latest release of %s", repo)
	}
	return rel.TagName, nil
}
