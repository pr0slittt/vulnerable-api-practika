"""
Detects information disclosure through undocumented GET /tokens endpoint
"""

from org.parosproxy.paros.network import HttpMessage
from org.zaproxy.zap.extension.ascan import AbstractPlugin, Plugin


class TokensInfoLeak(AbstractPlugin):

    def __init__(self):
        self.setId(300001)
        self.setName("Information Disclosure via GET /tokens")
        self.setCategory(Plugin.Category.INFO_DISCLOSURE)
        self.setRisk(Plugin.RISK_MEDIUM)
        self.setConfidence(Plugin.CONFIDENCE_HIGH)
        self.setDescription("GET /tokens is active and reveals sensitive user data including plaintext passwords.")
        self.setSolution("Remove the GET /tokens endpoint or restrict it with proper authentication and authorization.")
        self.setReference("https://owasp.org/www-project-api-security/")

    def scan(self):
        msg = self.getNewMsg()
        uri = msg.getRequestHeader().getURI()

        # Тестируем только /tokens (GET)
        uri.setPath("/tokens")
        msg.getRequestHeader().setMethod("GET")

        self.sendAndReceive(msg, False)

        body = msg.getResponseBody().toString()

        # Если ответ содержит вероятные поля пользователей — поднимаем алерт
        if "password" in body and "user" in body.lower():
            self.raiseAlert(
                self.getRisk(),
                self.getConfidence(),
                self.getName(),
                self.getDescription(),
                msg.getRequestHeader().getURI().toString(),
                "GET /tokens",
                "",
                "Response reveals user data including passwords.",
                self.getSolution(),
                self.getReference(),
                msg
            )

    def getId(self):
        return 300001
