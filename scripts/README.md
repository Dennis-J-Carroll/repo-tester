# 🔧 Security Fix Scripts

Automated tools to scan and fix vulnerabilities across your repositories.

## 📋 Scripts Overview

### 1. `bulk-fix-dependencies.sh` - Single Repo Fixer

**Purpose:** Fix vulnerabilities in a single repository

**Usage:**
```bash
# Fix current directory
./bulk-fix-dependencies.sh

# Fix specific repo
./bulk-fix-dependencies.sh /path/to/my-repo
```

**What it does:**
1. Backs up `requirements.txt`
2. Scans for vulnerabilities
3. Upgrades all packages to latest versions
4. Pins exact versions
5. Creates a git commit

---

### 2. `fix-all-my-repos.py` - Batch Repo Fixer

**Purpose:** Scan and fix ALL your GitHub repos automatically

**Prerequisites:**
```bash
# Install GitHub CLI
sudo apt install gh  # or: brew install gh

# Authenticate
gh auth login
```

**Usage:**
```bash
# Fix all repos for your account
python3 fix-all-my-repos.py

# Fix all repos for specific user
python3 fix-all-my-repos.py username
```

**What it does:**
1. Fetches all your GitHub repos
2. Scans each one for vulnerabilities
3. Asks permission before fixing each repo
4. Clones → upgrades → commits → pushes
5. Provides summary report

---

## 🚀 Quick Start Guide

### Scenario 1: Fix One Repo Manually

```bash
cd ~/my-vulnerable-repo
~/Desktop/repo-tester/scripts/bulk-fix-dependencies.sh
```

### Scenario 2: Fix All Your Repos

```bash
# Install dependencies
pip install repo-tester
gh auth login

# Run batch fixer
python3 ~/Desktop/repo-tester/scripts/fix-all-my-repos.py

# It will ask for each repo:
# Fix privacy-first-media-mix? (y/N/q): y
# Fix bayesian-analysis? (y/N/q): N
# Fix claude-desktop-bin? (y/N/q): q  # quit
```

---

## 🤖 GitHub Action (Automatic Scanning)

### Setup in Any Repo:

```bash
# In your project repo:
mkdir -p .github/workflows
cp ~/Desktop/repo-tester/.github/workflows/security-scan.yml .github/workflows/

# Commit and push
git add .github/workflows/security-scan.yml
git commit -m "ci: add automated security scanning"
git push
```

### What the Action Does:

- ✅ Runs on every push/PR
- ✅ Runs weekly on schedule
- ✅ Scans with `repo-tester`
- ✅ Comments on PRs with results
- ✅ Fails build if CRITICAL/HIGH issues
- ✅ Uploads results as artifacts

### View Results:

1. Go to GitHub → Your Repo → **Actions** tab
2. Click on a workflow run
3. See scan results in the summary
4. Download `security-scan-results` artifact

---

## 📊 Example Outputs

### Bulk Fix Script:
```
🔍 Bulk Dependency Fixer
━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository: /home/user/my-repo

📋 Step 1: Backing up requirements.txt
✅ Backup created: requirements.txt.bak.20260401_123456

📋 Step 2: Scanning for vulnerabilities
REPO SCAN: user/my-repo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[HIGH] Known CVEs in numpy: 16 vulnerabilities
[HIGH] Known CVEs in pillow: 112 vulnerabilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Step 3: Extracting package names
Found packages: numpy pandas scipy matplotlib

📋 Step 4: Upgrading packages to latest versions
  Upgrading numpy...
  Upgrading pandas...
  ...

📋 Step 7: Comparing changes
-numpy>=1.21.0
+numpy==1.26.4
-pandas
+pandas==2.2.1

📋 Commit these changes? (y/N): y
✅ Changes committed
```

---

## ⚙️ Configuration

### Customize GitHub Action:

Edit `.github/workflows/security-scan.yml`:

```yaml
# Run more frequently:
schedule:
  - cron: '0 9 * * *'  # Daily at 9am

# Only fail on CRITICAL:
- name: Fail if critical issues
  if: steps.parse.outputs.critical != '0'
  run: exit 1

# Disable PR comments:
# Comment out the "Comment on PR" step
```

---

## 🔒 Security Best Practices

### Before Bulk Fixing:

1. **Test locally first:**
   ```bash
   cd /tmp
   git clone your-repo test-fix
   cd test-fix
   ~/Desktop/repo-tester/scripts/bulk-fix-dependencies.sh
   # Test your app still works!
   ```

2. **Review changes:**
   - Check `git diff` before committing
   - Run your test suite
   - Verify nothing breaks

3. **Create feature branch:**
   ```bash
   git checkout -b security-updates
   ./bulk-fix-dependencies.sh
   git push -u origin security-updates
   # Create PR for review
   ```

### After Bulk Fixing:

1. **Run your test suite**
2. **Check CI/CD pipelines**
3. **Monitor for breakage**
4. **Update documentation** if API changes

---

## 🐛 Troubleshooting

### "gh: command not found"
```bash
# Install GitHub CLI:
# Ubuntu/Debian:
sudo apt install gh

# Mac:
brew install gh

# Then authenticate:
gh auth login
```

### "repo-tester: command not found"
```bash
pip install repo-tester
# or
cd ~/Desktop/repo-tester
pip install -e .
```

### Script fails with "No requirements.txt"
- The repo doesn't use Python/pip
- Try scanning manually: `repo-tester https://github.com/user/repo`

### Virtual environment errors
```bash
# Install venv if missing:
sudo apt install python3-venv
```

---

## 📚 Learn More

- **repo-tester docs:** See `CLAUDE.md` in parent directory
- **GitHub Actions:** https://docs.github.com/en/actions
- **OSV Database:** https://osv.dev/

---

## 🤝 Contributing

Found a bug or have suggestions? Open an issue!
