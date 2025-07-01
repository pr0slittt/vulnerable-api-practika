def scan(ps, msg, src):
    uri = msg.getRequestHeader().getURI().toString()
    if msg.getRequestHeader().getMethod() == 'GET' and '/tokens' in uri:
        body = msg.getResponseBody().toString()
        if 'password' in body or 'token' in body:
            ps.raiseAlert(
                risk=3,  # High
                confidence=3,
                name='Information Leakage via /tokens endpoint',
                description='Ответ GET /tokens содержит чувствительные данные (password/token).',
                uri=uri,
                param='',
                attack='',
                otherInfo='',
                solution='Ограничить доступ к эндпоинту или не возвращать пароли.',
                evidence=body,
                cweId=200,  # Information Exposure
                wascId=13
            )
