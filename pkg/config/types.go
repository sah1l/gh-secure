package config

type MergeStrategy struct {
	AllowSquash bool `yaml:"allow_squash" json:"allow_squash"`
	AllowMerge  bool `yaml:"allow_merge" json:"allow_merge"`
	AllowRebase bool `yaml:"allow_rebase" json:"allow_rebase"`
}

type BranchProtConfig struct {
	RequiredReviews      int      `yaml:"required_reviews" json:"required_reviews"`
	DismissStaleReviews  bool     `yaml:"dismiss_stale_reviews" json:"dismiss_stale_reviews"`
	RequireCodeOwners    bool     `yaml:"require_code_owners" json:"require_code_owners"`
	RequiredStatusChecks []string `yaml:"required_status_checks,omitempty" json:"required_status_checks,omitempty"`
	StrictStatusChecks   bool     `yaml:"strict_status_checks" json:"strict_status_checks"`
	EnforceAdmins        bool     `yaml:"enforce_admins" json:"enforce_admins"`
	AllowForcePushes     bool     `yaml:"allow_force_pushes" json:"allow_force_pushes"`
	AllowDeletions       bool     `yaml:"allow_deletions" json:"allow_deletions"`
	RequireLinearHistory bool     `yaml:"require_linear_history" json:"require_linear_history"`
	RequireSignedCommits bool     `yaml:"require_signed_commits" json:"require_signed_commits"`
}

type RulesetConfig struct {
	Name                 string   `yaml:"name" json:"name"`
	Target               string   `yaml:"target" json:"target"`
	Enforcement          string   `yaml:"enforcement" json:"enforcement"`
	Branches             []string `yaml:"branches" json:"branches"`
	RequiredReviews      int      `yaml:"required_reviews,omitempty" json:"required_reviews,omitempty"`
	DismissStaleReviews  bool     `yaml:"dismiss_stale_reviews,omitempty" json:"dismiss_stale_reviews,omitempty"`
	RequireCodeOwners    bool     `yaml:"require_code_owners,omitempty" json:"require_code_owners,omitempty"`
	RequireLinearHistory bool     `yaml:"require_linear_history,omitempty" json:"require_linear_history,omitempty"`
	RequireSignedCommits bool     `yaml:"require_signed_commits,omitempty" json:"require_signed_commits,omitempty"`
	PreventDeletion      bool     `yaml:"prevent_deletion,omitempty" json:"prevent_deletion,omitempty"`
	PreventForcePush     bool     `yaml:"prevent_force_push,omitempty" json:"prevent_force_push,omitempty"`
}

type SecurityConfig struct {
	VulnerabilityAlerts    bool `yaml:"vulnerability_alerts" json:"vulnerability_alerts"`
	AutomatedSecurityFixes bool `yaml:"automated_security_fixes" json:"automated_security_fixes"`
	SecretScanning         bool `yaml:"secret_scanning" json:"secret_scanning"`
	SecretScanningPushProt bool `yaml:"secret_scanning_push_protection" json:"secret_scanning_push_protection"`
	DependabotConfig       bool `yaml:"dependabot_config" json:"dependabot_config"`
}

type Config struct {
	Version             int               `yaml:"version" json:"version"`
	Visibility          string            `yaml:"visibility,omitempty" json:"visibility,omitempty"`
	License             string            `yaml:"license,omitempty" json:"license,omitempty"`
	MergeStrategy       MergeStrategy     `yaml:"merge_strategy" json:"merge_strategy"`
	DeleteBranchOnMerge bool              `yaml:"delete_branch_on_merge" json:"delete_branch_on_merge"`
	BranchProtection    *BranchProtConfig `yaml:"branch_protection,omitempty" json:"branch_protection,omitempty"`
	Rulesets            []RulesetConfig   `yaml:"rulesets,omitempty" json:"rulesets,omitempty"`
	Security            SecurityConfig    `yaml:"security" json:"security"`
	Files               []string          `yaml:"files,omitempty" json:"files,omitempty"`
}
