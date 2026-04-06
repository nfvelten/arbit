#!/usr/bin/env bash
# scripts/migrate-issues.sh
#
# Migrates all issues (open + closed) from nfvelten/arbitus to
# arbitusgateway/arbitus, preserving title, body, labels, and state.
#
# Usage:
#   bash scripts/migrate-issues.sh
#
# Requirements:
#   - gh CLI authenticated with write access to both repos
#   - jq installed

set -euo pipefail

SRC="nfvelten/arbitus"
DST="arbitusgateway/arbitus"
DELAY=1   # seconds between creates to stay under GitHub secondary rate limits

echo "Migrating issues from $SRC → $DST"
echo ""

# Ensure labels exist in destination before creating issues
echo "Syncing labels..."
gh label list --repo "$SRC" --limit 100 --json name,color,description \
  | jq -c '.[]' \
  | while IFS= read -r label; do
      name=$(echo "$label" | jq -r '.name')
      color=$(echo "$label" | jq -r '.color')
      desc=$(echo "$label" | jq -r '.description // ""')
      gh label create "$name" --repo "$DST" --color "$color" --description "$desc" --force 2>/dev/null || true
    done
echo "Labels synced."
echo ""

# Fetch all issues (open + closed), oldest first so numbers are roughly preserved
issues=$(gh issue list --repo "$SRC" \
  --limit 500 \
  --state all \
  --json number,title,body,labels,state \
  | jq -c 'sort_by(.number)[]')

total=$(echo "$issues" | wc -l | tr -d ' ')
count=0

echo "$issues" | while IFS= read -r issue; do
  count=$((count + 1))
  number=$(echo "$issue" | jq -r '.number')
  title=$(echo "$issue"  | jq -r '.title')
  body=$(echo "$issue"   | jq -r '.body // ""')
  state=$(echo "$issue"  | jq -r '.state')
  labels=$(echo "$issue" | jq -r '[.labels[].name] | join(",")')

  # Prepend original issue number to body for traceability
  full_body="$(printf '_Migrated from %s#%s_\n\n%s' "$SRC" "$number" "$body")"

  args=(--repo "$DST" --title "$title" --body "$full_body")
  [[ -n "$labels" ]] && args+=(--label "$labels")

  new_url=$(gh issue create "${args[@]}")
  new_number=$(echo "$new_url" | grep -o '[0-9]*$')

  # Close if it was closed in the source
  if [[ "$state" == "CLOSED" ]]; then
    gh issue close "$new_number" --repo "$DST" 2>/dev/null || true
  fi

  echo "  [$count/$total] #$number → $new_url ($state)"
  sleep "$DELAY"
done

echo ""
echo "Migration complete."
