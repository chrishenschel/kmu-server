#!/bin/bash
# Set Nextcloud Mail app default account to Stalwart (mail.DOMAIN).
# New users get a pre-configured mail account; they may need to enter their
# mail password once (same as Authentik/Stalwart) if using OIDC.
# Run from repo root. Requires .env with DOMAIN.
# Use: ./scripts/nextcloud-mail-default.sh

set -e
cd "$(dirname "$0")/.."

if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

if [ -z "${DOMAIN:-}" ]; then
    echo "ERROR: DOMAIN not set. Source .env or export it." >&2
    exit 1
fi

if ! docker exec --user www-data nextcloud php occ status 2>/dev/null | grep -q "installed: true"; then
    echo "ERROR: Nextcloud is not installed." >&2
    exit 1
fi

echo "Enabling Mail app..."
docker exec --user www-data nextcloud php occ app:enable mail 2>/dev/null || true

echo "Setting Mail app default account (Stalwart at mail.${DOMAIN})..."
# %EMAIL% is replaced by the user's email from their profile (from OIDC)
# IMAP/SMTP use same host; Stalwart uses 993 IMAPS and 465 SMTPS
MAIL_JSON=$(cat <<EOF
{
  "email": "%EMAIL%",
  "imapHost": "mail.${DOMAIN}",
  "imapPort": 993,
  "imapSslMode": "ssl",
  "imapUser": "%EMAIL%",
  "smtpHost": "mail.${DOMAIN}",
  "smtpPort": 465,
  "smtpSslMode": "ssl",
  "smtpUser": "%EMAIL%"
}
EOF
)

# Nextcloud stores this in system config; key may be app.mail.accounts.default
docker exec --user www-data nextcloud php occ config:system:set app.mail.accounts.default --value="$MAIL_JSON" --type=json 2>/dev/null && echo "Done (config:system:set)." || {
    echo "Trying app config..."
    docker exec --user www-data nextcloud php occ config:app:set mail accounts.default --value="$MAIL_JSON" --type=json 2>/dev/null && echo "Done (config:app:set)." || {
        echo "Could not set via occ. Add manually in Nextcloud:"
        echo "  Admin → Groupware → Mail → Default account / Provisioning"
        echo "  Or add to config/config.php:"
        echo "  'app.mail.accounts.default' => array("
        echo "    'email' => '%EMAIL%',"
        echo "    'imapHost' => 'mail.${DOMAIN}',"
        echo "    'imapPort' => 993,"
        echo "    'imapSslMode' => 'ssl',"
        echo "    'smtpHost' => 'mail.${DOMAIN}',"
        echo "    'smtpPort' => 465,"
        echo "    'smtpSslMode' => 'ssl',"
        echo "  ),"
    }
}

echo ""
echo "Note: With OIDC login, users have no password stored in Nextcloud."
echo "They may need to enter their mail (Authentik/Stalwart) password once"
echo "in the Mail app when opening the account, or set an app password in"
echo "Nextcloud settings."
