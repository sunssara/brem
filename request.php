<?php
declare(strict_types=1);
// BREM request endpoint. Recipient and sender are fixed; visitor data never sets recipients.
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

function respond(int $status, array $data): void {
    if ($status >= 400 && !empty($GLOBALS['captchaConsumed'])) $data['captcha_refresh'] = true;
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

set_exception_handler(function (Throwable $error): void {
    error_log('BREM request handler: ' . get_class($error));
    respond(500, ['ok' => false, 'message' => 'Не удалось отправить запрос. Напишите на info@brem.kz.']);
});

session_name('brem_request');
if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
} else {
    session_set_cookie_params(0, '/; samesite=Strict', '', true, true);
}
ini_set('session.use_strict_mode', '1');
if (!session_start()) {
    respond(503, ['ok' => false, 'message' => 'Форма временно недоступна. Напишите на info@brem.kz.']);
}
$method = $_SERVER['REQUEST_METHOD'] ?? '';
// Images contain paths, never the answer as text or metadata. Answers stay in the session.
function challenge(): array {
    $now = time();
    $pending = $_SESSION['challenges'] ?? [];
    foreach ($pending as $id => $item) if ((int)($item['expires'] ?? 0) < $now) unset($pending[$id]);
    $pending = array_slice($pending, -4, null, true);
    $id = bin2hex(random_bytes(16));
    $answer = '';
    for ($i = 0; $i < 5; $i++) $answer .= (string)random_int(0, 9);
    $pending[$id] = ['digest' => hash_hmac('sha256', $id . ':' . $answer, $_SESSION['csrf']), 'expires' => $now + 600];
    $_SESSION['challenges'] = $pending;
    $glyphs = [
        'M5 3Q0 3 0 18Q0 33 8 33Q16 33 16 18Q16 3 8 3Z',
        'M2 9L9 3V33M2 33H16',
        'M0 9Q3 0 11 4Q21 9 12 18L0 32H17',
        'M0 6Q16 -2 16 10Q16 18 7 18Q19 16 17 27Q13 38 0 30',
        'M12 33V3L0 24H18',
        'M17 3H2L1 17Q20 12 17 26Q14 38 0 30',
        'M15 4Q0 -2 0 22Q0 36 10 33Q20 29 15 19Q10 12 0 20',
        'M0 3H18L5 33',
        'M8 18Q-3 15 1 7Q8 -2 16 6Q22 15 8 18Q-4 22 2 30Q11 38 17 29Q22 22 8 18',
        'M1 30Q17 38 17 14Q17 0 6 4Q-4 9 2 19Q8 26 17 16'
    ];
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="210" height="64" viewBox="0 0 210 64"><rect width="210" height="64" rx="9" fill="#f1f3ec"/>';
    for ($i = 0; $i < 16; $i++) $svg .= '<circle cx="'.random_int(2,208).'" cy="'.random_int(2,62).'" r="1.2" fill="#aab6a3" opacity=".5"/>';
    for ($i = 0; $i < 5; $i++) {
        $x = 16 + $i * 38; $y = random_int(10,18); $angle = random_int(-10,10);
        $svg .= '<g transform="translate('.$x.' '.$y.') rotate('.$angle.' 9 18)"><path d="'.$glyphs[(int)$answer[$i]].'" fill="none" stroke="#26372b" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></g>';
    }
    $svg .= '<path d="M3 40Q62 22 110 39T207 27" fill="none" stroke="#a8b39f" stroke-width="1" opacity=".6"/></svg>';
    return ['id' => $id, 'image' => 'data:image/svg+xml;base64,' . base64_encode($svg), 'expires_in' => 600];
}
if ($method === 'GET') {
    if (empty($_SESSION['csrf']) || (int)($_SESSION['issued'] ?? 0) < time() - 7200) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        $_SESSION['issued'] = time();
    }
    respond(200, ['token' => $_SESSION['csrf'], 'captcha' => challenge()]);
}
if ($method !== 'POST') {
    header('Allow: GET, POST');
    respond(405, ['ok' => false, 'message' => 'Метод не поддерживается.']);
}
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 12 * 1024 * 1024) {
    respond(413, ['ok' => false, 'message' => 'Размер файла превышает 10 МБ.', 'errors' => ['specification' => 'Размер файла превышает 10 МБ.']]);
}
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0 && empty($_POST) && empty($_FILES)) respond(413, ['ok'=>false,'message'=>'Размер файла превышает 10 МБ.','errors'=>['specification'=>'Размер файла превышает 10 МБ.']]);
require_once __DIR__ . '/request-validation.php';
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && !in_array($origin, ['https://brem.kz', 'https://www.brem.kz'], true)) {
    respond(403, ['ok' => false, 'message' => 'Обновите страницу и повторите отправку.']);
}
$token = $_POST['csrf'] ?? '';
if (!is_string($token) || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token) || (int)($_SESSION['issued'] ?? 0) < time() - 7200) {
    respond(403, ['ok' => false, 'captcha_refresh' => true, 'message' => 'Сессия формы истекла. Повторите отправку.']);
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
$errors = [];
if ($name === '') $errors['name'] = 'Укажите имя.';
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email)) $errors['email'] = 'Укажите корректный email.';
if ($consent !== 'yes') $errors['consent'] = 'Подтвердите согласие на обработку данных.';
if ($phone !== '' && (!preg_match('/^[+0-9()\s.\-]{5,40}$/', $phone) || strlen(preg_replace('/\D/', '', $phone)) < 5)) $errors['phone'] = 'Проверьте номер телефона.';
$attachment = brem_attachment();
if ($message === '' && !$attachment) $errors['message'] = 'Опишите задачу или приложите спецификацию.';
if ($errors) respond(422, ['ok'=>false, 'message'=>'Проверьте отмеченные поля.', 'errors'=>$errors]);
$allowed = ['Помогите выбрать решение','Вычислительная инфраструктура','Корпоративные сети','Инженерные системы','Информационная безопасность','Техническая безопасность','Мультимедиа и AV-системы','Корпоративные коммуникации','Оборудование и ПО','Сервис и сопровождение'];
if (!in_array($service, $allowed, true)) {
    respond(422, ['ok' => false, 'message' => 'Выберите направление из списка.']);
}

// Count CAPTCHA attempts across sessions; forwarded headers cannot bypass this limit.
$attemptPath = sys_get_temp_dir() . '/brem-captcha-' . substr(hash('sha256', __DIR__), 0, 20) . '.json';
$attemptHandle = @fopen($attemptPath, 'c+');
if (!$attemptHandle || !flock($attemptHandle, LOCK_EX)) {
    if (is_resource($attemptHandle)) fclose($attemptHandle);
    respond(503, ['ok' => false, 'message' => 'Форма временно недоступна. Напишите на info@brem.kz.']);
}
@chmod($attemptPath, 0600);
$attempts = json_decode(stream_get_contents($attemptHandle), true);
if (!is_array($attempts)) $attempts = [];
$now = time();
foreach ($attempts as $key => $item) if (!is_array($item) || (int)($item['start'] ?? 0) < $now - 900) unset($attempts[$key]);
$attemptKey = hash('sha256', __DIR__ . '|' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
$attempt = $attempts[$attemptKey] ?? ['start' => $now, 'count' => 0];
$allAttempts = $attempts['all'] ?? ['start' => $now, 'count' => 0];
if ((int)$attempt['count'] >= 20 || (int)$allAttempts['count'] >= 500) {
    flock($attemptHandle, LOCK_UN); fclose($attemptHandle);
    header('Retry-After: 900');
    respond(429, ['ok' => false, 'message' => 'Слишком много попыток проверки. Попробуйте через 15 минут или напишите на info@brem.kz.']);
}
$attempt['count']++; $allAttempts['count']++;
$attempts[$attemptKey] = $attempt; $attempts['all'] = $allAttempts;
rewind($attemptHandle); ftruncate($attemptHandle, 0); fwrite($attemptHandle, json_encode($attempts)); fflush($attemptHandle);
flock($attemptHandle, LOCK_UN); fclose($attemptHandle);
$captchaId = field('captcha_id', 64);
$captchaAnswer = field('captcha', 32);
$storedChallenge = $_SESSION['challenges'][$captchaId] ?? null;
unset($_SESSION['challenges'][$captchaId]);
$GLOBALS['captchaConsumed'] = true;
if (!preg_match('/^[0-9]{5}$/D', $captchaAnswer) || !$storedChallenge || (int)$storedChallenge['expires'] < time() || !hash_equals($storedChallenge['digest'], hash_hmac('sha256', $captchaId . ':' . $captchaAnswer, $_SESSION['csrf']))) {
    respond(422, ['ok' => false, 'message' => 'Код неверный или устарел. Введите цифры с нового изображения.']);
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
$mime = brem_mail_content($body, $attachment);
$headers = [
    'From' => 'BREM Website <info@brem.kz>',
    'Reply-To' => $email,
    'MIME-Version' => '1.0',
    'Content-Type' => $mime['type'],
    'Content-Transfer-Encoding' => $mime['encoding'],
    'X-BREM-Request' => $reference
];
$accepted = function_exists('mail') && @mail('info@brem.kz', $subject, $mime['body'], $headers);
if (!$accepted) {
    error_log('BREM mail transport rejected request ' . $reference);
    respond(503, ['ok' => false, 'message' => 'Не удалось отправить запрос. Напишите на info@brem.kz или свяжитесь с нами в WhatsApp: 8 708 147 07 85.']);
}
unset($_SESSION['csrf'], $_SESSION['issued'], $_SESSION['challenges']);
respond(200, ['ok' => true, 'reference' => $reference]);
