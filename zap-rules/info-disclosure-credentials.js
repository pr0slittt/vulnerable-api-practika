// info-disclosure-credentials.js
// Это кастомное пассивное правило ZAP для обнаружения потенциального раскрытия учетных данных
// в телах ответов HTTP.

// Определяем, что это пассивное правило сканирования.
extension.addPassiveScanner(this);

/**
 * Имя сканера, которое будет отображаться в отчетах ZAP.
 */
function getName() {
    return "Custom Rule: Potential Credential Information Disclosure";
}

/**
 * Идентификатор сканера. Должен быть уникальным.
 * OWASP ZAP использует целочисленные идентификаторы для правил.
 * Вы можете выбрать число выше 90000, чтобы избежать конфликтов со встроенными правилами.
 */
function getId() {
    return 90001;
}

/**
 * Определяет, является ли правило активным. Для пассивного сканирования всегда 'false'.
 */
function is){
    return false;
}

/**
 * Основная функция пассивного сканирования.
 * Вызывается для каждого HTTP-сообщения (запроса и ответа).
 * @param {HttpMessage} msg - Объект HTTP-сообщения, содержащий запрос и ответ.
 * @param {HistoryReference} ref - Ссылка на историю сообщения.
 * @param {Alerts} alerts - Объект для создания предупреждений.
 */
function scan(msg, ref, alerts) {
    // Получаем тело ответа как строку.
    var responseBody = msg.getResponseBody().toString();

    // Регулярные выражения для поиска потенциальных учетных данных.
    // Это простые примеры, которые могут давать ложные срабатывания.
    // В реальных условиях нужны более точные паттерны.
    var patterns = [
        /(password|passwd|pwd)\s*=\s*['"]?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]+)['"]?/gi,
        /apiKey\s*:\s*['"]?([a-zA-Z0-9]{16,64})['"]?/gi,
        /secret(?:Key)?\s*:\s*['"]?([a-zA-Z0-9]{16,64})['"]?/gi,
        /token\s*:\s*['"]?([a-zA-Z0-9\-_=\.]{20,})['"]?/gi,
        /credentials\s*:\s*\{[^}]*username\s*:\s*['"][^'"]+['"],?\s*password\s*:\s*['"][^'"]+['"]}/gi
    ];

    var found = false;
    for (var i = 0; i < patterns.length; i++) {
        var match;
        while ((match = patterns[i].exec(responseBody)) !== null) {
            found = true;
            // Создаем предупреждение ZAP.
            // Параметры:
            //   id (int): Идентификатор правила
            //   alertType (int): Тип предупреждения (например, HIGH, MEDIUM, LOW)
            //   risk (int): Уровень риска (например, Alert.RISK_HIGH)
            //   confidence (int): Уровень достоверности (например, Alert.CONFIDENCE_MEDIUM)
            //   name (string): Имя предупреждения
            //   description (string): Описание уязвимости
            //   uri (string): URL, на котором обнаружена уязвимость
            //   param (string): Параметр или поле, связанное с уязвимостью
            //   attack (string): Используемый метод атаки (для пассивного - обычно "N/A")
            //   evidence (string): Часть сообщения, подтверждающая уязвимость
            //   solution (string): Рекомендации по исправлению
            //   references (string): Ссылки на дополнительную информацию
            //   cweId (int): Идентификатор CWE (Common Weakness Enumeration)
            //   wascId (int): Идентификатор WASC (Web Application Security Consortium)

            alerts.new => {
                setPluginId(getId());
                setAlert(getName());
                setRisk(Alert.RISK_HIGH); // Высокий риск
                setConfidence(Alert.CONFIDENCE_MEDIUM); // Средняя достоверность
                setDescription('Обнаружено потенциальное раскрытие учетных данных (например, паролей, ключей API, секретов) в теле ответа HTTP. Это может привести к несанкционированному доступу к конфиденциальной информации или системам.');
                setUri(msg.getRequestHeader().getURI().toString());
                setParam(match[0]); // Показываем найденный паттерн как параметр
                setAttack(''); // Для пассивных сканов нет активной атаки
                setEvidence(match[0]); // Найденный фрагмент как доказательство
                setSolution('Избегайте передачи конфиденциальных данных, таких как учетные данные, ключи API или токены, в открытом виде в ответах HTTP. Используйте безопасные механизмы передачи данных (например, HTTP-заголовки авторизации, безопасные куки). Убедитесь, что логирование не сохраняет чувствительную информацию.');
                setReference('OWASP Top 10:2021 - A01:2021-Broken Access Control, A04:2021-Insecure Design (Information Disclosure)\nCWE-200: Exposure of Sensitive Information to an Unauthorized Actor\nCWE-522: Insufficiently Protected Credentials');
                setCweId(200); // Пример CWE ID
                setWascId(13); // Пример WASC ID
            }).raise();
        }
    }
}
