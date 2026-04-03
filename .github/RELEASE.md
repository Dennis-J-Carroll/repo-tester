# Release Process Documentation

This document provides a complete step-by-step guide for releasing repo-tester to PyPI, including OIDC configuration, GitHub environment setup, and verification procedures.

## Table of Contents

1. [OIDC Configuration](#oidc-configuration)
2. [GitHub Environment Setup](#github-environment-setup)
3. [Release Workflow](#release-workflow)
4. [Verification](#verification)
5. [Rollback Procedures](#rollback-procedures)

## OIDC Configuration

### TestPyPI OIDC Setup

1. **Navigate to TestPyPI Settings**
   - Visit https://test.pypi.org/manage/account/
   - Go to "Publishing" section
   - Click "Add a new pending publisher"

2. **Configure Publisher Details**
   - **PyPI Project Name:** repo-tester
   - **Owner (username or organization):** Dennis-J-Carroll
   - **Repository name:** repo-tester
   - **Repository owner:** Dennis-J-Carroll
   - **Workflow name:** publish.yml
   - **Environment name:** (leave blank - no environment required)
   - Click "Add" to save

3. **Verify Configuration**
   - The publisher will appear in "Pending publishers" list
   - Status should show as "Pending" until first successful publish
   - After first publish, status changes to "Active"

### PyPI OIDC Setup

1. **Navigate to PyPI Settings**
   - Visit https://pypi.org/manage/account/
   - Go to "Publishing" section
   - Click "Add a new pending publisher"

2. **Configure Publisher Details**
   - **PyPI Project Name:** repo-tester
   - **Owner (username or organization):** Dennis-J-Carroll
   - **Repository name:** repo-tester
   - **Repository owner:** Dennis-J-Carroll
   - **Workflow name:** publish.yml
   - **Environment name:** release
   - Click "Add" to save

3. **Verify Configuration**
   - The publisher will appear in "Pending publishers" list
   - Status shows as "Pending" until first successful publish
   - Will become "Active" after first successful release

## GitHub Environment Setup

### Create GitHub Environments

1. **Navigate to Repository Settings**
   - Go to https://github.com/Dennis-J-Carroll/repo-tester/settings
   - Click "Environments" in the left sidebar

2. **Create Release Environment for PyPI**
   - Click "New environment"
   - Name: `release`
   - Click "Configure environment"
   - No deployment branches required for OIDC
   - No secrets required for OIDC
   - Save environment
   - Note: TestPyPI does not require a GitHub environment (no environment specified in test-publish job)

### Verify GitHub Actions OIDC Permissions

1. **Check Repository Permissions**
   - Go to Settings → "Actions" → "General"
   - Under "Workflow permissions", ensure:
     - "Read and write permissions" is selected
     - "Allow GitHub Actions to create and approve pull requests" is checked

2. **Verify Workflow File**
   - The `.github/workflows/publish.yml` file should contain:
     - `permissions: { id-token: write, contents: read }`
     - Environment specification for each PyPI job
     - Proper PyPA publish action configuration

## Release Workflow

### Pre-Release Checklist

1. **Update Version Numbers**
   ```bash
   # Update version in pyproject.toml
   # Current version: 0.1.0
   # Update to: 0.2.0 (for minor release)
   ```

2. **Update CHANGELOG**
   - Add entry for new version with date
   - Document all changes, features, and fixes
   - Link to relevant GitHub issues and PRs

3. **Run Full Test Suite**
   ```bash
   pytest -v
   # All tests must pass
   ```

4. **Run Security Scan**
   ```bash
   bandit -r src/repo_tester/
   # No critical security issues allowed
   ```

5. **Build and Verify Local Artifacts**
   ```bash
   rm -rf dist/ build/ src/repo_tester.egg-info/
   python -m build
   python -m zipfile -l dist/repo_tester-*.whl | head -20
   tar -tzf dist/repo_tester-*.tar.gz | grep -E "(README|LICENSE|SECURITY|pyproject)"
   ```

### Release to TestPyPI

1. **Create and Push Release Tag**
   ```bash
   # Create annotated tag for release
   git tag -a v0.2.0 -m "Release version 0.2.0"
   
   # Push tag to trigger workflow
   git push origin v0.2.0
   ```

2. **Monitor GitHub Actions Workflow**
   - Go to https://github.com/Dennis-J-Carroll/repo-tester/actions
   - Select "publish" workflow
   - Monitor the build and publish steps
   - Wait for successful completion

3. **Verify TestPyPI Package**
   ```bash
   # Check package page
   # https://test.pypi.org/project/repo-tester/
   
   # Install from TestPyPI (optional)
   python -m venv test-verify
   source test-verify/bin/activate
   pip install --index-url https://test.pypi.org/simple/ repo-tester
   repo-tester --help
   ```

### Release to Production PyPI

1. **Final Verification**
   - Confirm all TestPyPI tests passed
   - Verify package works with test installation
   - Ensure all documentation is accurate

2. **Trigger Production Release**
   - The publish workflow will attempt to publish to PyPI
   - Environment name: `release` (requires OIDC trust from PyPI)
   - GitHub Actions will use OIDC token to authenticate

3. **Monitor Production Release**
   - Go to https://github.com/Dennis-J-Carroll/repo-tester/actions
   - Check "publish" workflow final step
   - Wait for successful PyPI publication

4. **Verify Production Package**
   ```bash
   # Check package page
   # https://pypi.org/project/repo-tester/
   
   # Install from PyPI
   pip install repo-tester
   repo-tester --help
   repo-tester https://github.com/owner/repo
   ```

## Verification

### Post-Release Verification Steps

1. **Check PyPI Package Page**
   - Navigate to https://pypi.org/project/repo-tester/
   - Verify correct version is displayed
   - Check that README renders properly
   - Confirm description, keywords, and metadata are correct
   - Verify all classifiers are present
   - Check that GitHub links resolve correctly

2. **Test Installation from PyPI**
   ```bash
   python -m venv verify-env
   source verify-env/bin/activate
   pip install repo-tester
   
   # Verify CLI works
   repo-tester --help
   
   # Test with actual repository
   repo-tester https://github.com/Dennis-J-Carroll/repo-tester --quiet
   
   # Clean up
   deactivate
   rm -rf verify-env
   ```

3. **Verify Package Contents**
   ```bash
   pip show repo-tester
   # Check that version, location, and dependencies are correct
   ```

4. **Test Import in Python**
   ```python
   import repo_tester
   from repo_tester.cli import main
   from repo_tester.scanners import BaseScanner
   print("All imports successful")
   ```

5. **Check GitHub Release Page**
   - Navigate to https://github.com/Dennis-J-Carroll/repo-tester/releases
   - Verify tag was created
   - Create release notes if desired
   - Link to PyPI package page

## Rollback Procedures

### If Release Fails on PyPI

1. **Immediate Actions**
   - Check GitHub Actions logs for specific error
   - Common issues:
     - Package name already exists (use new version)
     - OIDC token issue (verify environment setup)
     - Malformed metadata (check pyproject.toml)

2. **Fix and Retry**
   - Correct the identified issue
   - Create new version number
   - Push new tag to trigger workflow again
   - Do NOT reuse the same version number

3. **Check PyPI Quarantine Status**
   - PyPI holds first-time uploads for review
   - Monitor PyPI project page
   - Contact PyPI support if blocked longer than expected

### If Release Needs to be Yanked

1. **Yank Package Version from PyPI**
   - Go to https://pypi.org/project/repo-tester/
   - Click on specific version number
   - Click "Release history" or "Files"
   - Find "Yank release" option
   - Confirm yanking

2. **Notify Users**
   - Create GitHub issue explaining yank reason
   - Post in relevant communication channels
   - Update documentation if needed

3. **Create New Release**
   - Increment version number
   - Address the issue that caused yank
   - Follow complete release workflow again

### Rolling Back to Previous Version

If production release has critical issues:

1. **Mark Current Release as Yanked** (if already on PyPI)
   - Follow "Yank Package Version" steps above

2. **Document the Issue**
   - Create GitHub issue with full details
   - Tag as `urgent` or `critical`
   - Post post-mortem findings

3. **Re-Release Previous Version**
   - Check out previous release tag
   - Verify it builds and works
   - Create new tag for "hotfix" release
   - Push to trigger workflow

4. **Fix Root Cause**
   - Create feature branch
   - Implement fixes with tests
   - Merge to master
   - Create next version release

## Security Considerations

### OIDC Security Best Practices

1. **Token Validation**
   - GitHub Actions OIDC tokens are short-lived (1 minute)
   - PyPI validates token issuer and claims
   - No credentials stored in GitHub Secrets

2. **Repository Protection**
   - Use branch protection rules
   - Require code review before release
   - Restrict who can push tags
   - Enable status checks before merge

3. **Audit Trail**
   - GitHub Actions logs all publish attempts
   - PyPI audit logs show all uploads
   - Review both logs after each release

### Dependency Verification

Before release, verify all dependencies:
```bash
pip-audit
# Scan for known vulnerabilities
```

## Troubleshooting

### Common Issues and Solutions

**Issue: "Package already exists"**
- Solution: Increment version number in pyproject.toml
- PyPI does not allow version reuse

**Issue: "OIDC token verification failed"**
- Solution: Verify environment name matches in GitHub and PyPI/TestPyPI settings
- Check that workflow file uses correct environment

**Issue: "Metadata is invalid"**
- Solution: Validate pyproject.toml syntax
- Ensure README.md exists and is readable
- Check for special characters in description

**Issue: "First-time package held for review"**
- Solution: This is normal for new packages on PyPI
- Wait for PyPI moderators to approve
- Usually resolves within hours
- Check PyPI project page for status

**Issue: "Wheel file not found"**
- Solution: Ensure `python -m build` completes successfully
- Check that build artifacts exist in dist/
- Verify no build errors in logs

## Additional Resources

- [PyPI Publishing Guide](https://packaging.python.org/tutorials/packaging-projects/)
- [GitHub Actions OIDC Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [PyPA Build Tool Documentation](https://pypa-build.readthedocs.io/)
- [repo-tester Repository](https://github.com/Dennis-J-Carroll/repo-tester)

## Version History

| Version | Date | Status |
|---------|------|--------|
| 0.1.0 | 2026-04-03 | Initial release |
| 0.2.0+ | TBD | Future releases |
