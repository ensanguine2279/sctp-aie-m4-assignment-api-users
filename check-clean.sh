#!/usr/bin/env bash
#
# Check for uncommitted changes and presence of sensitive files (.pem and .env)
#
# Usage:
#   ./check-clean.sh
#

git status
git ls-files | grep -E '\.pem$|^\.env$' || echo "clean"