<?php
declare(strict_types=1);
// BREM request endpoint. Recipient and sender are fixed; visitor data never sets recipients.
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

function respond(int $status, array $data): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

set_exception_handler(function (Throwable $error): void {
    error_log('BREM request handler: ' . get_class($error));
    respond(500, ['ok' => false, 'message' => 'Не удалось отправить запрос. Напишите на info@brem.kz.']);
});

session_name('brem_request');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
ini_set('session.use_strict_mode', '1');
if (!session_start()) {
    respond(503, ['ok' => false, 'message' => 'Форма временно недоступна. Напишите на info@brem.kz.']);
}
$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method === 'GET') {
    if (empty($_SESSION['csrf']) || (int)($_SESSION['issued'] ?? 0) < time() - 7200) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        $_SESSION['issued'] = time();
    }
    respond(200, ['token' => $_SESSION['csrf']]);
}
if ($method !== 'POST') {
    header('Allow: GET, POST');
    respond(405, ['ok' => false, 'message' => 'Метод не поддерживается.']);
}
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 20000) {
    respond(413, ['ok' => false, 'message' => 'Слишком длинное сообщение.']);
}
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && !in_array($origin, ['https://brem.kz', 'https://www.brem.kz'], true)) {
    respond(403, ['ok' => false, 'message' => 'Обновите страницу и повторите отправку.']);
}
$token = $_POST['csrf'] ?? '';
if (!is_string($token) || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token) || (int)($_SESSION['issued'] ?? 0) < time() - 7200) {
    respond(403, ['ok' => false, 'message' => 'Сессия формы истекла. Повторите отправку.']);
}

function field(string $name, int $max): string {
    $value = $_POST[$name] ?? '';
    if (!is_string($value) || strlen($value) > $max || preg_match('//u', $value) !== 1) {
        respond(422, ['ok' => false, 'message' => 'Проверьте заполненные поля и длину сообщения.']);
    }
    return trim(str_replace(["\0", "\r"], '', $value));
}
$name = field('name', 400);
$company = field('company', 640);
$email = field('email', 254);
$phone = field('phone', 160);
$service = field('service', 500);
$message = field('message', 16000);
$honeypot = field('website', 1000);
$consent = field('consent', 10);
if ($honeypot !== '' || time() - (int)$_SESSION['issued'] < 2) {
    respond(422, ['ok' => false, 'message' => 'Пожалуйста, проверьте поля и повторите отправку через несколько секунд.']);
}
if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email) || $consent !== 'yes') {
    respond(422, ['ok' => false, 'message' => 'Укажите имя, корректный e-mail и согласие на обработку данных.']);
}
if ($phone !== '' && (!preg_match('/^[+0-9()\s.\-]{5,40}$/', $phone) || strlen(preg_replace('/\D/', '', $phone)) < 5)) {
    respond(422, ['ok' => false, 'message' => 'Проверьте номер телефона.']);
}
$allowed = ['Помогите выбрать решение','Вычислительная инфраструктура','Корпоративные сети','Инженерные системы','Информационная безопасность','Техническая безопасность','Мультимедиа и AV-системы','Корпоративные коммуникации','Оборудование и ПО','Сервис и сопровождение'];
if (!in_array($service, $allowed, true)) {
    respond(422, ['ok' => false, 'message' => 'Выберите направление из списка.']);
}

// A single locked file outside the document root limits repeated requests, including fresh sessions.
// Store only hashed network identifiers, timestamps and counters, never submitted personal data.
$ratePath = sys_get_temp_dir() . '/brem-request-' . substr(hash('sha256', __DIR__), 0, 20) . '.json';
$handle = @fopen($ratePath, 'c+');
if (!$handle || !flock($handle, LOCK_EX)) {
    if (is_resource($handle)) fclose($handle);
    respond(503, ['ok' => false, 'message' => 'Форма временно недоступна. Напишите на info@brem.kz.']);
}
@chmod($ratePath, 0600);
$rates = json_decode(stream_get_contents($handle), true);
if (!is_array($rates)) $rates = [];
$now = time();
foreach ($rates as $key => $record) {
    if (!is_array($record) || (int)($record['start'] ?? 0) < $now - 3600) unset($rates[$key]);
}
$key = hash('sha256', (__DIR__ . '|' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')));
$record = $rates[$key] ?? ['start' => $now, 'last' => 0, 'count' => 0];
$global = $rates['all'] ?? ['start' => $now, 'last' => 0, 'count' => 0];
if ($now - (int)$record['last'] < 60 || (int)$record['count'] >= 5 || (int)$global['count'] >= 100) {
    flock($handle, LOCK_UN); fclose($handle);
    header('Retry-After: 60');
    respond(429, ['ok' => false, 'message' => 'Запрос уже отправлялся недавно. Пожалуйста, попробуйте позже или напишите на info@brem.kz.']);
}
$record['last'] = $now; $record['count']++;
$global['last'] = $now; $global['count']++;
$rates[$key] = $record; $rates['all'] = $global;
rewind($handle); ftruncate($handle, 0);
fwrite($handle, json_encode($rates)); fflush($handle);
flock($handle, LOCK_UN); fclose($handle);

$reference = 'BR-' . gmdate('ymd') . '-' . strtoupper(bin2hex(random_bytes(3)));
$body = "Новая заявка с brem.kz\nНомер: $reference\n\nИмя: $name\nКомпания: $company\nE-mail: $email\nТелефон: $phone\nНаправление: $service\n\nЗадача:\n$message\n\nСогласие на обработку данных: получено\n";
$subject = '=?UTF-8?B?' . base64_encode('BREM — заявка с сайта ' . $reference) . '?=';
$headers = [
    'From' => 'BREM Website <info@brem.kz>',
    'Reply-To' => $email,
    'MIME-Version' => '1.0',
    'Content-Type' => 'text/plain; charset=UTF-8',
    'Content-Transfer-Encoding' => 'base64',
    'X-BREM-Request' => $reference
];
$accepted = function_exists('mail') && @mail('info@brem.kz', $subject, chunk_split(base64_encode($body), 76, "\r\n"), $headers);
if (!$accepted) {
    error_log('BREM mail transport rejected request ' . $reference);
    respond(503, ['ok' => false, 'message' => 'Не удалось отправить запрос. Напишите на info@brem.kz или позвоните +7 (7172) 72-49-52.']);
}
unset($_SESSION['csrf'], $_SESSION['issued']);
respond(200, ['ok' => true, 'reference' => $reference]);
