<?php
declare(strict_types=1);
// Included by request.php; never stores uploaded files in the web root.
function brem_file_error(string $message): void {
    respond(422, ['ok'=>false, 'message'=>$message, 'errors'=>['specification'=>$message]]);
}
function brem_attachment(): ?array {
    if (count($_FILES) > 1 || (count($_FILES) && !isset($_FILES['specification']))) brem_file_error('Прикрепите только один файл.');
    $file = $_FILES['specification'] ?? null;
    if ($file === null) return null;
    if (!is_array($file) || !isset($file['error']) || is_array($file['error'])) brem_file_error('Прикрепите только один файл.');
    $error = (int)$file['error'];
    if ($error === UPLOAD_ERR_NO_FILE) return null;
    if ($error === UPLOAD_ERR_INI_SIZE || $error === UPLOAD_ERR_FORM_SIZE) brem_file_error('Размер файла превышает 10 МБ.');
    if ($error !== UPLOAD_ERR_OK) brem_file_error('Не удалось загрузить файл. Выберите его снова.');
    if (!isset($file['tmp_name'], $file['name']) || !is_string($file['tmp_name']) || !is_string($file['name']) || !is_uploaded_file($file['tmp_name'])) brem_file_error('Не удалось загрузить файл. Выберите его снова.');
    $size = filesize($file['tmp_name']);
    if ($size === false || $size === 0) brem_file_error('Файл пуст. Выберите другой файл.');
    if ($size > 10 * 1024 * 1024) brem_file_error('Размер файла превышает 10 МБ.');
    $name = basename(str_replace('\\', '/', $file['name']));
    if (preg_match('//u', $name) !== 1 || preg_match('/[\x00-\x1f\x7f]/', $name) || strlen($name)>240) brem_file_error('Файл повреждён или содержит неподдерживаемые элементы.');
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $types = ['pdf'=>'application/pdf','docx'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.document','xlsx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','csv'=>'text/csv'];
    if (!isset($types[$ext])) brem_file_error('Допустимы файлы PDF, DOCX, XLSX и CSV.');
    $path = $file['tmp_name'];
    $head = file_get_contents($path, false, null, 0, 16);
    if ($ext === 'pdf') {
        $tail = file_get_contents($path, false, null, max(0, $size-2048));
        if (!(strncmp($head, '%PDF-', 5) === 0) || strpos($tail, '%%EOF') === false) brem_file_error('Содержимое файла не соответствует его формату.');
    } elseif ($ext === 'csv') {
        $text = file_get_contents($path);
        if (preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $text) || (strncmp($head, 'PK', 2) === 0) || preg_match('/^\s*<(?:\?php|html|!doctype)/i', $text)) brem_file_error('Содержимое файла не соответствует его формату.');
        // CSV is transferred as a file; its cells are never evaluated on the server.
    } else {
        if (!class_exists('ZipArchive')) respond(503,['ok'=>false,'message'=>'Проверка DOCX и XLSX временно недоступна. Приложите PDF или CSV либо опишите задачу.','errors'=>['specification'=>'Проверка DOCX и XLSX временно недоступна. Приложите PDF или CSV либо опишите задачу.']]);
        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::CHECKCONS) !== true) brem_file_error('Содержимое файла не соответствует его формату.');
        $total = 0; $valid = $zip->numFiles <= 2000;
        for ($i=0; $valid && $i<$zip->numFiles; $i++) {
            $entry = $zip->statIndex($i); $entryName = $entry['name'] ?? '';
            $total += (int)($entry['size'] ?? 0);
            if ($total>50*1024*1024 || (int)($entry['size']??0)>20*1024*1024 || ($entry['encryption_method']??0)!==0 || preg_match('~(^/|(^|/)\.\.(/|$)|\\\\|vbaProject|\.(exe|dll|js|vbs|ps1|bat|cmd|scr)$)~i',$entryName)) $valid=false;
        }
        $main = $ext==='docx'?'word/document.xml':'xl/workbook.xml';
        $type = $ext==='docx'?'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml';
        $typesXml = $valid ? $zip->getFromName('[Content_Types].xml', 1024*1024) : false;
        $mainXml = $valid ? $zip->getFromName($main, 20*1024*1024) : false;
        $zip->close();
        if (!$valid || !$typesXml || !$mainXml || strpos($typesXml,$type)===false || stripos($typesXml,'<!DOCTYPE')!==false || stripos($mainXml,'<!DOCTYPE')!==false) brem_file_error('Файл повреждён или содержит неподдерживаемые элементы.');
        $xml = new DOMDocument();
        if (!@$xml->loadXML($mainXml, LIBXML_NONET)) brem_file_error('Файл повреждён или содержит неподдерживаемые элементы.');
        $expected = $ext==='docx'?'document':'workbook';
        if ($xml->documentElement->localName!==$expected) brem_file_error('Содержимое файла не соответствует его формату.');
    }
    return ['name'=>$name,'path'=>$path,'type'=>$types[$ext],'size'=>$size];
}
function brem_mail_content(string $body, ?array $attachment): array {
    if (!$attachment) return ['type'=>'text/plain; charset=UTF-8','encoding'=>'base64','body'=>chunk_split(base64_encode($body),76,"\r\n")];
    $boundary = 'brem_' . bin2hex(random_bytes(18));
    $encodedName = rawurlencode($attachment['name']);
    $fallback = 'specification.' . strtolower(pathinfo($attachment['name'], PATHINFO_EXTENSION));
    $message = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($body),76,"\r\n");
    $message .= "--$boundary\r\nContent-Type: {$attachment['type']}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"$fallback\"; filename*=UTF-8''$encodedName\r\n\r\n";
    $message .= chunk_split(base64_encode(file_get_contents($attachment['path'])),76,"\r\n") . "--$boundary--\r\n";
    return ['type'=>'multipart/mixed; boundary="'.$boundary.'"','encoding'=>'7bit','body'=>$message];
}
