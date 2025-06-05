package models

type GitHubSearchItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	URL        string `json:"url"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
}

type GitHubSearchResponse struct {
	TotalCount int                 `json:"total_count"`
	Items      []GitHubSearchItem `json:"items"`
}

type PoCData struct {
	CVEID    string
	Source   string
	RepoURL  string
	FileURL  string
	Content  string
}
