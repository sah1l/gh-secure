package templates

import "fmt"

// CodeOfConduct returns a reference to the Contributor Covenant v2.1.
// The full text is not embedded — instead we link to the canonical source.
func CodeOfConduct(repoName, owner string) string {
	return fmt.Sprintf(`# Contributor Covenant Code of Conduct

This project has adopted the [Contributor Covenant](https://www.contributor-covenant.org/) version 2.1 as its Code of Conduct.

The full text is available at: https://www.contributor-covenant.org/version/2/1/code_of_conduct/

## Our Pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone, regardless of background or identity.

## Enforcement

Instances of unacceptable behavior may be reported to the project maintainers
at [@%s](https://github.com/%s).

Project maintainers are responsible for clarifying and enforcing standards of
acceptable behavior and will take appropriate action in response to any behavior
that they deem inappropriate.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org),
version 2.1.
`, owner, owner)
}
