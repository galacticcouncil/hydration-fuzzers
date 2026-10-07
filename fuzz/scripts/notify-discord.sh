#!/usr/bin/env bash
# Post a message (stdin) to the Discord webhook. The URL comes from $DISCORD_WEBHOOK, or from
# $DISCORD_WEBHOOK_FILE (default ~/.config/hydration-fuzz/discord-webhook; a bare URL or a .env-style
# DISCORD_WEBHOOK=... line), and is never printed.
#   echo "text" | scripts/notify-discord.sh          exit 0 = delivered (HTTP 2xx)
#                                              exit 2 = not configured (no request made)
#                                              exit 1 = delivery failed after retries
set -euo pipefail
# URL source, in order: $DISCORD_WEBHOOK, the file (bare URL or a DISCORD_WEBHOOK=... line), else unconfigured.
F=${DISCORD_WEBHOOK_FILE:-$HOME/.config/hydration-fuzz/discord-webhook}
URL=${DISCORD_WEBHOOK:-}
if [ -z "$URL" ] && [ -r "$F" ]; then
	URL=$(grep -E '^DISCORD_WEBHOOK=' "$F" | head -1 | cut -d= -f2- || true)
	[ -n "$URL" ] || URL=$(cat "$F")
fi
URL=$(printf '%s' "$URL" | tr -d '[:space:]"'"'")
if [ -z "$URL" ]; then
	echo "webhook not configured (no DISCORD_WEBHOOK env and no $F); nothing sent" >&2
	exit 2
fi
MSG=$(cat)
# Discord limit is 2000 chars; cut at 1900 and mark it.
PAYLOAD=$(MSG="$MSG" python3 -c 'import json,os; m=os.environ["MSG"]; m=m if len(m)<=1900 else m[:1900]+"\n…(truncated)"; print(json.dumps({"content": m, "username": "hydration-fuzz"}))')
for attempt in 1 2 3; do
	code=$(curl -sS -o /tmp/notify-discord.$$ -w '%{http_code}' --max-time 15 --max-redirs 0 \
		-H 'Content-Type: application/json' -X POST --data "$PAYLOAD" "$URL" 2>/dev/null) || code=000
	case "$code" in
		2??) rm -f /tmp/notify-discord.$$; exit 0 ;;
		429) wait=$(python3 -c 'import json,sys; print(int(float(json.load(open(sys.argv[1])).get("retry_after",2)))+1)' /tmp/notify-discord.$$ 2>/dev/null || echo 3); sleep "$wait" ;;
		5??|000) sleep $((attempt * 2)) ;;
		*) echo "webhook rejected the message: HTTP $code" >&2; rm -f /tmp/notify-discord.$$; exit 1 ;;
	esac
done
echo "webhook delivery failed after 3 attempts (last HTTP $code)" >&2
rm -f /tmp/notify-discord.$$
exit 1
