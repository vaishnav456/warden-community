package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Read metadata or restore through fresh grants; server never receives file
// contents or the Home encryption key. All requests stay on configured nodes.
func homeHistoryJob(p map[string]interface{}) (int, string, error) {
	username, _ := p["username"].(string)
	spaceID, _ := p["space_id"].(string)
	path, _ := p["path"].(string)
	action, _ := p["action"].(string)
	if !identityUsernamePattern.MatchString(username) {
		return 1, "", errors.New("invalid username")
	}
	clean, err := cleanHomePart(path)
	if err != nil {
		return 1, "", err
	}
	if action != "list" && action != "restore" {
		return 1, "", errors.New("invalid history action")
	}
	result, err := apiPostAuth("/api/agent/home-config", map[string]interface{}{"username": username})
	if err != nil {
		return 1, "", err
	}
	encoded, err := json.Marshal(result["home"])
	if err != nil {
		return 1, "", err
	}
	var spaces []homeSpace
	if err = json.Unmarshal(encoded, &spaces); err != nil {
		return 1, "", err
	}
	for _, space := range spaces {
		if space.ID != spaceID {
			continue
		}
		allowed := false
		for _, mapping := range space.Mappings {
			if strings.HasPrefix(clean, strings.Trim(mapping.Target, "/")+"/") {
				allowed = true
			}
		}
		if !allowed {
			return 1, "", errors.New("file is outside assigned mappings")
		}
		if action == "restore" && (space.AccessMode == "read" || space.SyncMode == "download") {
			return 1, "", errors.New("space is read-only")
		}
		remotePath := strings.Trim(space.Prefix, "/") + "/" + clean
		for _, node := range space.Nodes {
			if !node.Writable {
				continue
			}
			for _, candidate := range homeNodeCandidates(node) {
				client, err := homeHTTPClient(candidate, username)
				if err != nil {
					continue
				}
				expected := ""
				if action == "restore" {
					files, _, err := listHomeFilesTracked(client, candidate, space.Prefix)
					if err != nil {
						continue
					}
					for _, file := range files {
						if file.Path == remotePath {
							expected = file.SHA256
							if file.Deleted {
								expected = fmt.Sprintf("%s:%d", file.SHA256, file.ModTime)
							}
						}
					}
				}
				method := http.MethodGet
				version, _ := p["version_id"].(string)
				if action == "restore" {
					method = http.MethodPost
				}
				req, err := http.NewRequest(method, homeNodeURL(candidate)+"/v1/history?path="+url.QueryEscape(remotePath)+"&version="+url.QueryEscape(version), nil)
				if err != nil {
					return 1, "", err
				}
				req.Header.Set("Authorization", "Bearer "+candidate.Grant)
				req.Header.Set("X-Warden-Expected-Version", expected)
				response, err := client.Do(req)
				if err != nil {
					continue
				}
				raw, readErr := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
				response.Body.Close()
				if readErr != nil || len(raw) > 256*1024 {
					return 1, "", errors.New("history response too large or incomplete")
				}
				if response.StatusCode < 200 || response.StatusCode >= 300 {
					return 1, "", fmt.Errorf("history HTTP %d: %s", response.StatusCode, string(raw))
				}
				var versions []map[string]interface{}
				if action == "list" && json.Unmarshal(raw, &versions) != nil {
					return 1, "", errors.New("invalid history response")
				}
				output, _ := json.Marshal(map[string]interface{}{"kind": "warden_home_history", "space_id": spaceID, "path": clean, "action": action, "versions": versions, "restored_sha256": response.Header.Get("X-Warden-SHA256")})
				return 0, string(output), nil
			}
		}
		return 1, "", errors.New("writable Home node is unavailable")
	}
	return 1, "", errors.New("space is no longer assigned")
}
