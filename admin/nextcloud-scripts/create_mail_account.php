<?php
/**
 * Create a Nextcloud Mail account for a user (Stalwart/IMAP).
 * Run inside Nextcloud container with env: NC_MAIL_UID, NC_MAIL_EMAIL, NC_MAIL_PASSWORD, NC_MAIL_HOST.
 * Example: docker exec -i -e NC_MAIL_UID=user -e NC_MAIL_EMAIL=user@domain -e NC_MAIL_HOST=mail.domain nextcloud php /usr/local/nextcloud-scripts/create_mail_account.php
 */
if (php_sapi_name() !== 'cli') {
    die('CLI only');
}

$uid = getenv('NC_MAIL_UID');
$email = getenv('NC_MAIL_EMAIL');
$password = getenv('NC_MAIL_PASSWORD');
if ($password === false || $password === '') {
    $password = stream_get_contents(STDIN);
    if ($password !== false) {
        $password = trim($password);
    }
}
$mailHost = getenv('NC_MAIL_HOST') ?: 'localhost';

if (!$uid || !$email || $password === false || $password === '') {
    fwrite(STDERR, "Missing: NC_MAIL_UID, NC_MAIL_EMAIL, and NC_MAIL_PASSWORD (or stdin)\n");
    exit(1);
}

// Bootstrap Nextcloud (run as www-data, no HTTP user yet)
require_once '/var/www/html/lib/base.php';

$userManager = \OC::$server->getUserManager();
if (!$userManager->userExists($uid)) {
    fwrite(STDERR, "User not found: $uid\n");
    exit(1);
}

// Ensure mail app is enabled
$appManager = \OC::$server->getAppManager();
if (!$appManager->isEnabledForUser('mail', $userManager->get($uid))) {
    $appManager->enableApp('mail');
}

// Act as the target user so Mail app creates the account in their context
\OC::$server->getUserSession()->loginAsUser($userManager->get($uid));

try {
    $accountService = \OC::$server->get(\OCA\Mail\Service\AccountService::class);
} catch (Throwable $e) {
    fwrite(STDERR, "AccountService: " . $e->getMessage() . "\n");
    exit(1);
}

$account = new \OCA\Mail\Db\MailAccount([
    'accountName' => $email,
    'emailAddress' => $email,
    'imapHost' => $mailHost,
    'imapPort' => 993,
    'imapSslMode' => 'ssl',
    'imapUser' => $email,
    'imapPassword' => $password,
    'smtpHost' => $mailHost,
    'smtpPort' => 465,
    'smtpSslMode' => 'ssl',
    'smtpUser' => $email,
    'smtpPassword' => $password,
]);
$account->setUserId($uid);
$account->setAuthMethod('password');
$account->setOrder(1);

try {
    $accountService->save($account);
    echo "OK\n";
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, "Save failed: " . $e->getMessage() . "\n");
    exit(1);
}
