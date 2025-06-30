#!/bin/bash

# Array of generic commit messages
messages=(
    "Initial commit"
    "Update configuration"
    "Add features"
    "Update code"
    "Update documentation"
    "Add configuration"
    "Update structure"
    "Update build"
    "Update package"
    "Update configuration"
    "Update server"
    "Update functionality"
    "Update structure"
    "Update build"
    "Update configuration"
    "Update server"
    "Update protocol"
    "Update codebase"
    "Update files"
    "Update validation"
)

# Get list of commit hashes in reverse order (oldest first)
commits=($(git log --oneline --reverse | cut -d' ' -f1))

echo "Found ${#commits[@]} commits to rewrite"
echo "Will use ${#messages[@]} generic messages"

# Start interactive rebase from root
export GIT_SEQUENCE_EDITOR="sed -i 's/^pick/reword/g'"
git rebase -i --root

# The rebase will now prompt for each commit message
# We'll handle this in the commit-msg hook temporarily
