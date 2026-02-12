package templates

import (
	"fmt"
	"strings"
)

func Dependabot(ecosystems []string) string {
	var b strings.Builder
	b.WriteString("version: 2\nupdates:\n")

	for _, eco := range ecosystems {
		dir := "/"
		b.WriteString(fmt.Sprintf(`  - package-ecosystem: "%s"
    directory: "%s"
    schedule:
      interval: "weekly"
`, eco, dir))
	}

	return b.String()
}

// DefaultDependabot returns a dependabot config with github-actions at minimum.
func DefaultDependabot() string {
	return `version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
`
}
