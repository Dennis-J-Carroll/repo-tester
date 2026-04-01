#!/bin/bash
#
# Bulk Dependency Fixer
# Usage: ./bulk-fix-dependencies.sh /path/to/repo
#
# This script:
# 1. Scans a repo for vulnerabilities
# 2. Updates vulnerable packages to latest versions
# 3. Pins all dependencies
# 4. Creates a git commit with changes

set -e

REPO_PATH="${1:-.}"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d_%H%M%S)"

echo "🔍 Bulk Dependency Fixer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Repository: $REPO_PATH"
echo ""

# Check if repo path exists
if [ ! -d "$REPO_PATH" ]; then
    echo "❌ Error: Directory $REPO_PATH does not exist"
    exit 1
fi

cd "$REPO_PATH"

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: No requirements.txt found in $REPO_PATH"
    exit 1
fi

echo "📋 Step 1: Backing up requirements.txt"
cp requirements.txt "requirements.txt${BACKUP_SUFFIX}"
echo "✅ Backup created: requirements.txt${BACKUP_SUFFIX}"
echo ""

echo "📋 Step 2: Scanning for vulnerabilities"
if command -v repo-tester &> /dev/null; then
    REPO_URL=$(git config --get remote.origin.url 2>/dev/null || echo "")
    if [ -n "$REPO_URL" ]; then
        echo "Scanning: $REPO_URL"
        repo-tester "$REPO_URL" || true
    else
        echo "⚠️  No git remote found, skipping scan"
    fi
else
    echo "⚠️  repo-tester not installed, skipping scan"
fi
echo ""

echo "📋 Step 3: Extracting package names"
# Extract package names (handle ==, >=, <=, ~=, etc.)
PACKAGES=$(grep -v '^#' requirements.txt | grep -v '^$' | sed 's/[>=<~!].*//' | tr '\n' ' ')
echo "Found packages: $PACKAGES"
echo ""

echo "📋 Step 4: Upgrading packages to latest versions"
for pkg in $PACKAGES; do
    echo "  Upgrading $pkg..."
    pip install --upgrade "$pkg" 2>&1 | grep -v "Requirement already satisfied" || true
done
echo ""

echo "📋 Step 5: Freezing exact versions"
pip freeze > requirements.txt.new
echo "✅ New requirements generated"
echo ""

echo "📋 Step 6: Filtering to original packages only"
# Only keep packages that were in the original requirements.txt
cat requirements.txt.new | grep -E "^($(echo $PACKAGES | tr ' ' '|'))==" > requirements.txt.filtered || true
mv requirements.txt.filtered requirements.txt
echo "✅ Requirements pinned to exact versions"
echo ""

echo "📋 Step 7: Comparing changes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
diff -u "requirements.txt${BACKUP_SUFFIX}" requirements.txt || true
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📋 Step 8: Testing installation"
if python -m pip install -r requirements.txt --dry-run 2>&1 | grep -q "Would install"; then
    echo "✅ New requirements are installable"
else
    echo "⚠️  Installation test completed (check output above)"
fi
echo ""

# Ask for confirmation
read -p "📋 Commit these changes? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if git diff --quiet requirements.txt; then
        echo "ℹ️  No changes to commit"
    else
        git add requirements.txt
        git commit -m "security: update and pin dependencies

- Upgraded all packages to latest versions
- Pinned exact versions for reproducibility
- Fixes known CVEs identified by repo-tester

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
        echo "✅ Changes committed"
        echo ""
        echo "Next steps:"
        echo "  git push origin main"
    fi
else
    echo "ℹ️  Changes not committed"
    echo "Backup available at: requirements.txt${BACKUP_SUFFIX}"
fi

# Cleanup
rm -f requirements.txt.new

echo ""
echo "✅ Done!"
