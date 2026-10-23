<?php
declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');
printf("PHP_VERSION=%s\n", PHP_VERSION);
printf("PHP_SAPI=%s\n", php_sapi_name());
printf("MEMORY_LIMIT=%s\n", ini_get('memory_limit'));
printf("SESSION_UPLOAD_PROGRESS=%s\n", ini_get('session.upload_progress.enabled'));
printf("SESSION_UPLOAD_PROGRESS_NAME=%s\n", ini_get('session.upload_progress.name'));
printf("ROLE=%s\n", PHP_VERSION === '8.4.26' ? 'vulnerable' : (PHP_VERSION === '8.4.27' ? 'patched' : 'unknown'));

