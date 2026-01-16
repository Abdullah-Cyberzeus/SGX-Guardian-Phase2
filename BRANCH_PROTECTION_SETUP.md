# Branch Protection Setup Guide

This guide will help you configure branch protection rules for the `main` branch to support trunk-based development while allowing repository admins to bypass all rules.

## Prerequisites

- You must be a repository administrator
- GitHub Actions workflow must be committed and pushed to the repository

## Steps to Configure Branch Protection

### 1. Navigate to Branch Protection Settings

1. Go to your GitHub repository
2. Click on **Settings** tab
3. In the left sidebar, click **Branches** (under "Code and automation")
4. Click **Add branch protection rule** (or **Add rule**)

### 2. Configure the Branch Name Pattern

- **Branch name pattern**: `main`

### 3. Enable Required Status Checks

Check the following options:

- ✅ **Require status checks to pass before merging**
  - ✅ **Require branches to be up to date before merging**
  - Under "Status checks that are required", add these checks:
    - `test`
    - `security`
    - `status-check`

### 4. Enable Pull Request Requirements

- ✅ **Require a pull request before merging**
  - **Required number of approvals before merging**: Set to `1` (or your preferred number)
  - ✅ **Dismiss stale pull request approvals when new commits are pushed**
  - ✅ **Require review from Code Owners** (optional, if you have CODEOWNERS file)

### 5. Enable Additional Protections

- ✅ **Require conversation resolution before merging** (recommended)
- ✅ **Require signed commits** (optional, for enhanced security)
- ✅ **Require linear history** (recommended for trunk-based development)
- ✅ **Require deployments to succeed before merging** (optional)

### 6. Enable Bypass Permissions for Admins

**IMPORTANT**: Ensure the following settings:

- ✅ **Do not allow bypassing the above settings**
  - Then, under **Bypass list**, click **Add bypass**
  - Select **Repository admin** role
  - This allows you as an admin to bypass rules when necessary

OR (newer GitHub UI):

- ✅ **Allow specified actors to bypass required pull requests**
  - Add yourself or the admin role to the bypass list

### 7. Restrict Push Access

- ✅ **Restrict who can push to matching branches** (optional)
  - Add specific teams or users who can push (if desired)
  - As an admin, you can still bypass this

### 8. Save the Rule

- Click **Create** (or **Save changes**)

## Verification

After setting up the protection rules:

1. Try creating a new branch: `git checkout -b test-branch`
2. Make a change and push: `git push -u origin test-branch`
3. Create a pull request to `main`
4. Verify that the PR shows required status checks
5. Verify that you cannot merge until all checks pass
6. As an admin, verify you can bypass rules if needed (there will be a button/option to merge despite failing checks)

## Quick Reference - Recommended Settings

```
Branch name pattern: main

✅ Require status checks to pass before merging
   ✅ Require branches to be up to date before merging
   Required status checks: test, security, status-check

✅ Require a pull request before merging
   Required approvals: 1
   ✅ Dismiss stale pull request approvals when new commits are pushed

✅ Require conversation resolution before merging
✅ Require linear history

✅ Allow bypass for: Repository admins
```

## Notes for Trunk-Based Development

- **Short-lived feature branches**: Keep branches small and merge frequently
- **Continuous Integration**: The GitHub Actions workflow runs on every PR
- **Admin bypass**: Use sparingly, only for urgent hotfixes or administrative tasks
- **Linear history**: Helps maintain clean commit history (consider using squash merges)

## Troubleshooting

**Status checks not appearing?**
- Ensure the workflow file is committed to `main` branch
- Push a test branch and create a PR to trigger the workflow
- Check the Actions tab to see if workflows are running

**Cannot merge even though checks pass?**
- Verify required status check names match exactly: `test`, `security`, `status-check`
- Ensure branch is up to date with `main`

**Need to bypass as admin?**
- You should see additional options to merge despite failing checks
- Use the "Merge without waiting for requirements to be met" option if available
