package templates

import "fmt"

func Security(repoName, owner string) string {
	return fmt.Sprintf(`# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **%s**, please report it responsibly.

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to the maintainers or use [GitHub's private vulnerability reporting](https://github.com/%s/%s/security/advisories/new).

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix & Disclosure**: As soon as a fix is available

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

Thank you for helping keep %s secure!
`, repoName, owner, repoName, repoName)
}
