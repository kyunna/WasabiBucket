// Package models provides structures related to PoC (Proof of Concept) handling.
package models

// PoCInfo represents metadata for a specific PoC source.
type PoCInfo struct {
	CVEID       string
	Source      string
	URL         string
	Author      string
	Language    string
	Verified    bool
	Description string
}

// PoCFile describes an individual file related to a PoC.
type PoCFile struct {
	Path    string
	FileURL string
	FileExt string
}

// GroupedPoC combines PoC metadata with its associated files.
type GroupedPoC struct {
	Info  PoCInfo
	Files []PoCFile
}

// GitHubSearchItem mirrors the structure of GitHub's search API response.
type GitHubSearchItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
}

// GitHubSearchResponse represents the top-level GitHub API response.
type GitHubSearchResponse struct {
	TotalCount int                 `json:"total_count"`
	Items      []GitHubSearchItem `json:"items"`
}

// RepoMetadata contains simplified GitHub repository metadata.
type RepoMetadata struct {
	Language    string `json:"language"`
	Description string `json:"description"`
}
