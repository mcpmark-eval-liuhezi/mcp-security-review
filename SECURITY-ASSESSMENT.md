# MCP Server Security Assessment

**Purpose:** Security evaluation of three MCP server implementation candidates for internal tooling, prepared for the team sync.

**Scope:** For each candidate, the repository's published GitHub security advisories were checked. The results below are exactly what the advisory check returned.

---

## 1. github/github-mcp-server

**Repository:** `github/github-mcp-server`
**Description:** GitHub's official MCP Server (Go)

**Advisory check returned 2 published security advisories:**

| Advisory ID | CVE | Severity | Summary |
|---|---|---|---|
| GHSA-pjp5-fpmr-3349 | CVE-2026-48529 | Medium | Lockdown mode singleton in HTTP server causes cross-user GraphQL client confusion |
| GHSA-w4q6-qw23-4rg7 | CVE-2026-47427 | High | Nil Pointer Dereference DoS in completion/complete Handler |

**Details:**

- **GHSA-pjp5-fpmr-3349** (CVE-2026-48529, Medium, CVSS 6.0, CWE-284) — "Lockdown mode singleton in HTTP server causes cross-user GraphQL client confusion." When running the HTTP server with `--lockdown-mode`, the `RepoAccessCache` singleton is initialized with the first authenticated user's GraphQL client and never updated, so later users' lockdown queries run under the first user's credentials. Affected: `>= 0.22.0, < 1.1.2`; patched in 1.1.2.
- **GHSA-w4q6-qw23-4rg7** (CVE-2026-47427, High, CVSS 7.5, CWE-476) — "Nil Pointer Dereference DoS in completion/complete Handler." A malformed `completion/complete` request with missing/empty parameters panics the server before authentication, letting any unauthenticated client cause denial of service. Affected: `<= 0.33.0` (also affects latest main); no patched version listed at time of review.

**Verdict:** Conditionally acceptable — patch history is reasonable and the most impactful issue is DoS-only, but the unresolved nil-pointer DoS in `completion/complete` needs a fix or network-level mitigation before any internet-exposed deployment.

---

## 2. modelcontextprotocol/servers

**Repository:** `modelcontextprotocol/servers`
**Description:** Model Context Protocol Servers — the reference servers repository (TypeScript)

**Advisory check returned 6 published security advisories:**

| Advisory ID | CVE | Severity | Summary |
|---|---|---|---|
| GHSA-q66q-fx2p-7w4m | CVE-2025-53109 | High | Path validation bypass via symlink handling (server-filesystem) |
| GHSA-hc55-p739-j48w | CVE-2025-53110 | High | Path validation bypass via colliding path prefix (server-filesystem) |
| GHSA-5cgr-j3jf-jw3v | CVE-2025-68143 | Medium | Unrestricted git_init tool allows repository creation at arbitrary filesystem locations in mcp-server-git |
| GHSA-9xwc-hfwc-8w59 | CVE-2025-68144 | Medium | Argument injection in git_diff and git_checkout functions for mcp-server-git allows overwriting local files |
| GHSA-j22h-9j4x-23w5 | CVE-2025-68145 | Medium | Missing path validation when using --repository flag in mcp-server-git |
| GHSA-vjqx-cfc4-9h6v | CVE-2026-27735 | Medium | Path traversal in git_add allows staging files outside repository boundaries in mcp-server-git |

**Details:**

- **GHSA-q66q-fx2p-7w4m** (CVE-2025-53109, High) — "Path validation bypass via symlink handling." Filesystem server versions before 0.6.3 / 2025.3.28 could allow access to unintended files via symlinks within allowed directories. Fixed in 0.6.3 / 2025.7.01.
- **GHSA-hc55-p739-j48w** (CVE-2025-53110, High) — "Path validation bypass via colliding path prefix." Filesystem server versions before 0.6.3 / 2025.3.28 could allow access to unintended files where the prefix matches an allowed directory. Fixed in 0.6.3 / 2025.7.01.
- **GHSA-5cgr-j3jf-jw3v** (CVE-2025-68143, Medium, CWE-36) — "Unrestricted git_init tool allows repository creation at arbitrary filesystem locations in mcp-server-git." The `git_init` tool accepted arbitrary filesystem paths without validating the target location; the tool was removed entirely. Fixed in 2025.9.25.
- **GHSA-9xwc-hfwc-8w59** (CVE-2025-68144, Medium, CWE-88) — "Argument injection in git_diff and git_checkout functions for mcp-server-git allows overwriting local files." User-controlled arguments were passed to the git CLI without sanitization, so flag-like values (e.g., `--output=...`) could overwrite arbitrary files. Fixed in 2025.12.18.
- **GHSA-j22h-9j4x-23w5** (CVE-2025-68145, Medium, CWE-22) — "Missing path validation when using --repository flag in mcp-server-git." When started with `--repository`, tool-call `repo_path` arguments were not validated as within the configured path. Fixed in 2025.12.18.
- **GHSA-vjqx-cfc4-9h6v** (CVE-2026-27735, Medium, CWE-22) — "Path traversal in git_add allows staging files outside repository boundaries in mcp-server-git." `git_add` did not validate that file paths were within repository boundaries, allowing `../` sequences to stage files outside the repo. Fixed in 2026.1.14.

**Verdict:** Highest advisory count of the three and every issue is filesystem/argument handling that could expose host files — only adopt specific, up-to-date servers (notably git/filesystem ones) and restrict them to dedicated, least-privilege containers with tightly scoped allowed paths.

---

## 3. microsoft/playwright-mcp

**Repository:** `microsoft/playwright-mcp`
**Description:** Playwright MCP server (TypeScript)

**Advisory check returned no published security advisories — none were found.** The list of repository security advisories came back empty.

**Verdict:** Cleanest published-advisory record of the three; adopt, subject to normal dependency and behavioral review, with the standard caveat that absence of published advisories is not proof of absence of vulnerabilities.

---

## Summary table

| Candidate | Published advisories | Highest severity |
|---|---|---|
| `github/github-mcp-server` | 2 | High (DoS) |
| `modelcontextprotocol/servers` | 6 | High (filesystem access) |
| `microsoft/playwright-mcp` | 0 | — |

---

## Methodology notes

- Advisory checks were performed against each repository's published GitHub security advisories (repository-level advisories, state = published).
- Advisory IDs, CVEs, severities, and one-line summaries are recorded exactly as returned by the checks.
- Path and argument handling dominate the reference-servers findings, which is expected for tools that manipulate the local filesystem and shell out to git.
