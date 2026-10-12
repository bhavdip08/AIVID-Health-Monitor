# Push AIVID Health Monitor to your personal GitHub repository

These steps use your own GitHub account and run on your computer. They do not
install the monitor, restart your software or change your Kubernetes cluster.

## Create the destination

1. Sign in to your personal account at https://github.com/new.
2. Select your personal username under **Owner**.
3. Set the name to `aivid-health-monitors` and visibility to **Private**.
4. Leave **Add a README**, **Add .gitignore** and **Choose a license** unselected.
   This source package already supplies these files.
5. Create the repository and copy its HTTPS URL.

If the destination already contains commits, stop before these initial-import
commands and inspect its history. Do not use force-push to overwrite existing work.

## Extract the source

On a computer with Git and unzip installed, open a terminal in the download folder:

```bash
unzip AIVID-Health-Monitor-GitHub-Source.zip
cd aivid-health-monitors
```

The ZIP includes `.gitignore` and `.gitattributes`. Keep them in the folder.

## Authenticate locally

If GitHub CLI is installed:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
```

Complete browser authentication using your personal account. Otherwise use your
existing Git credential manager or an SSH key already registered with GitHub.
For HTTPS, an ordinary GitHub account password is not accepted for Git pushes.
Do not put tokens in the remote URL, source files or chat.

## Commit and push

Use your name and GitHub commit email (or GitHub noreply email) below.
The remote URL is your supplied personal repository. The configuration applies only to this
repository.

```bash
git init -b main
git config user.name "YOUR_NAME"
git config user.email "YOUR_GITHUB_EMAIL"
git add .
git diff --cached --stat
git commit -m "Update health monitor branding and customizable alerts"
git remote add origin https://github.com/bhavdip08/aivid-health-monitors.git
git push -u origin main
```

Use the exact repository URL if its name differs. After a successful push, refresh
GitHub and confirm that `backend`, `installer`, `tests`, `tools`, `packaging` and
`docs` appear, then check:

```bash
git status
git log -1 --oneline
git remote -v
```

The offline runtime is about 33 MiB, so browser drag-and-drop cannot upload the
complete tree. Every included file is below GitHub's 100 MiB Git-file limit;
Git LFS is not required for this initial import. Offline dependencies are included
intentionally to retain the current reproducible build inputs.

## Publish installers separately

After the source is pushed, attach the signed `.run`, its matching `.sha256`,
the signed release archive and manuals to a GitHub Release if you want downloadable
installers. Uploading source does not deploy the application or create a release.
Keep the repository private unless you decide to publish the proprietary code.

## Future updates

```bash
git pull --ff-only
git add backend installer tests tools docs README.md
git diff --cached --stat
git commit -m "Describe the change"
git push
```

Include other deliberately changed paths when appropriate. Never copy live
`node.json`, credentials, state databases or private signing/TLS keys into Git.

References:

- https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github
- https://docs.github.com/en/get-started/git-basics/managing-remote-repositories
- https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github

## Update an existing checkout

If the repository already contains commits, use a clean checkout of
`https://github.com/bhavdip08/aivid-health-monitors` and copy the updated source
folder contents into it. Preserve its `.git` directory and review your own local
changes first. Then review `git diff`, stage the intended files, commit the update
and run `git push`. Do not force-push or replace repository history. The source
ZIP is not itself the source tree; extract it before copying the files.
