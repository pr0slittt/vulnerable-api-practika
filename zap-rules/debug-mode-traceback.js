// debug-mode-traceback.js
// Это кастомное пассивное правило ZAP для обнаружения трассировок стека (stack traces)
// и указаний на режим отладки в ответах HTTP.

extension.addPassiveScanner(this);

function getName() {
    return "Custom Rule: Debug Mode/Stack Trace Disclosure";
}

function getId() {
    return 90002; // Уникальный ID для этого правила
}

function isPassive() {
    return true;
}

function scan(msg, ref, alerts) {
    var responseBody = msg.getResponseBody().toString();

    // Паттерны для обнаружения трассировок стека и признаков режима отладки
    // Это упрощенные паттерны, могут потребоваться более сложные.
    var stackTracePatterns = [
        /at org\.apache\.[a-zA-Z0-9\.]+\([a-zA-Z0-9\.]+\:\d+\)/gi, // Java stack trace
        /in line \d+ of [a-zA-Z0-9\/\-_\.]+\.php/gi, // PHP stack trace
        /File "[a-zA-Z0-9\/\-_\.]+\.py", line \d+/gi, // Python stack trace
        /Caused by:/gi,
        /Traceback \(most recent call last\):/gi,
        /debug=true/gi, // Прямое упоминание режима отладки (в коде/тексте)
        /Error: 500 Internal Server Error/gi, // Общая ошибка сервера
        /at System\.[a-zA-Z0-9\.]+\(/gi // .NET stack trace
    ];

    var found = false;
    for (var i = 0; i < stackTracePatterns.length; i++) {
        var match;
        while ((match = stackTracePatterns[i].exec(responseBody)) !== null) {
            found = true;
            alerts.new => {
                setPluginId(getId());
                setAlert(getName());
                setRisk(Alert.RISK_HIGH); // Высокий риск
                setConfidence(Alert.CONFIDENCE_MEDIUM); // Средняя достоверность
                setDescription('Обнаружено раскрытие отладочной информации, такой как трассировка стека или прямое указание на активный режим отладки, в ответе HTTP. Эта информация может помочь злоумышленнику понять внутреннюю структуру приложения, выявить используемые технологии и найти дополнительные уязвимости.');
                setUri(msg.getRequestHeader().getURI().toString());
                setParam(match[0]); // Найденный паттерн как параметр
                setAttack(''); // Для пассивных сканов нет активной атаки
                setEvidence(match[0]); // Найденный фрагмент как доказательство
                setSolution('Отключите режим отладки и подробное логирование ошибок в производственной среде. Настройте обработку ошибок таким образом, чтобы пользователям отображались только общие сообщения об ошибках, без раскрытия системной информации. Убедитесь, что трассировки стека и другая отладочная информация не попадают в HTTP-ответы.');
                setReference('OWASP Top 10:2021 - A01:2021-Broken Access Control (Information Disclosure), A04:2021-Insecure Design\nCWE-200: Exposure of Sensitive Information to an Unauthorized Actor\nCWE-215: Information Exposure Through Debug Information');
                setCweId(200); // Пример CWE ID
                setWascId(13); // Пример WASC ID
            }).raise();
        }
    }
}
