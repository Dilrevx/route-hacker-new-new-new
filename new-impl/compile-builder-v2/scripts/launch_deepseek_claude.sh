#!/usr/bin/env bash
# Launch a bounded Claude CLI worker with the user's existing DeepSeek profile.
#
# The provider function lives in ~/.bashrc and owns its credential values. This
# wrapper never prints or persists those values; it only passes the configured
# environment to the command supplied after "--".

set -eo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

if [[ ! -f "${HOME}/.bashrc" ]]; then
  echo "missing ~/.bashrc DeepSeek Claude profile" >&2
  exit 2
fi

# Loading the whole interactive profile can start proxy helpers. Extract only
# the existing function definition and its export statement instead. The
# profile's `sed -i` lines mutate user settings; suppress those because this
# worker needs its exported environment only.
source <(
  sed -n '/^function switch-claude()/,/^export -f switch-claude$/p' "${HOME}/.bashrc" |
    sed -E 's/^[[:space:]]*sed -i .*/: # settings mutation suppressed for worker/'
)
if ! declare -F switch-claude >/dev/null; then
  echo "switch-claude function is unavailable in ~/.bashrc" >&2
  exit 2
fi

# The function's non-interactive final test can return false after applying
# the profile; its exports are still valid for the child command.
switch-claude deepseek || true
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-${ANTHROPIC_AUTH_TOKEN:-}}"
if [[ -z "${ANTHROPIC_API_KEY}" ]]; then
  echo "DeepSeek Claude profile did not provide an API credential" >&2
  exit 2
fi

if [[ "$1" == -* ]]; then
  exec "${COMPILE_BUILDER_CLAUDE_BIN:-claude}" "$@"
fi

exec "$@"
