# GitLab to GitHub Migration Script

For migrating issues and merge requests from GitLab projects to GitHub repositories.

**Instructions**

1. Create empty repository in GitHub
2. Clone GitLab repository: `git clone --mirror <gitlab_repo>`
3. Change directory: `cd <repo_dir>`
4. Push to GitHub repository: `git push --mirror --no-verify <github_repo>`
5. In GitHub, goto **Settings > Branches**, then rename default branch to `main`
6. Download and extract the GitLab project export to a new working directory
7. Edit `settings.json`
8. Execute `gitlab-2-github.py`
