from org.apache.commons.httpclient import URI
from org.parosproxy.paros.core.scanner import Alert
from org.parosproxy.paros.network import (
    HttpHeader,
    HttpMessage,
    HttpRequestHeader,
    HttpSender,
)


def scan(msg, plugin):
    base_uri = msg.getRequestHeader().getURI()
    target_url = base_uri.getScheme() + "://" + base_uri.getHost() + ":" + str(base_uri.getPort()) + "/tokens"

    new_uri = URI(target_url, False)
    new_request_header = HttpRequestHeader()
    new_request_header.setMessage("GET", new_uri, "HTTP/1.1")

    new_msg = HttpMessage(new_request_header)
    http_sender = HttpSender(plugin.getModel().getHttpSender().getActiveScanInitiator())

    try:
        http_sender.sendAndReceive(new_msg, False)
    except Exception as e:
        plugin.getParent().handleException(e)
        return

    if new_msg.getResponseHeader().getStatusCode() == 200:
        response_body = new_msg.getResponseBody().toString()

        if "token" in response_body and "expires" in response_body and "issued_at" in response_body:
            plugin.bingo(
                Alert.RISK_HIGH,
                Alert.CONFIDENCE_HIGH,
                'Утечка Информации: Эндпоинт /tokens',
                'Эндпоинт ' + target_url + ' раскрывает токены пользователей или другие конфиденциальные данные.',
                target_url,
                'GET',
                '',
                response_body,
                'Ограничьте доступ к эндпоинту /tokens только для авторизованных запросов или удалите раскрытие чувствительной информации.',
                '',
                new_msg
            )
