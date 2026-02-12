package templates

import "fmt"

func Contributing(repoName, owner string) string {
	return fmt.Sprintf(`# Contributing to %s

Thank you for your interest in contributing! Here are some guidelines to help you get started.

## How to Contribute

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your changes
4. **Make your changes** and commit them with clear messages
5. **Push** your branch and open a **Pull Request**

## Reporting Issues

- Use GitHub Issues to report bugs or suggest features
- Provide as much detail as possible
- Include steps to reproduce for bug reports

## Pull Request Guidelines

- Keep PRs focused and small when possible
- Write clear commit messages
- Update documentation if needed
- Ensure all tests pass before submitting

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Questions?

Feel free to open an issue or reach out to [@%s](https://github.com/%s).
`, repoName, owner, owner)
}
