package burp

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import http.BinaryHttpRequestTranslator

internal interface MontoyaRequestFactory {
    fun normalized(service: HttpService, raw: String): HttpRequest
    fun header(name: ByteArray, value: ByteArray): HttpHeader
    fun bytes(value: ByteArray): MontoyaByteArray
    fun http2(service: HttpService, headers: List<HttpHeader>, body: MontoyaByteArray): HttpRequest
}

private object DefaultMontoyaRequestFactory : MontoyaRequestFactory {
    override fun normalized(service: HttpService, raw: String) = HttpRequest.httpRequest(service, raw)

    override fun header(name: ByteArray, value: ByteArray) = HttpHeader.httpHeader(name, value)

    override fun bytes(value: ByteArray) = MontoyaByteArray.byteArray(*value)

    override fun http2(service: HttpService, headers: List<HttpHeader>, body: MontoyaByteArray) =
        HttpRequest.http2Request(service, headers, body)
}

internal class BurpMontoyaRequestBuilder(
    private val factory: MontoyaRequestFactory = DefaultMontoyaRequestFactory,
) {
    fun build(
        service: HttpService,
        raw: String,
        kettled: Boolean,
        useHTTP1: Boolean,
    ): HttpRequest {
        if (!kettled || useHTTP1) return factory.normalized(service, raw)

        val scheme = if (service.secure()) "https" else "http"
        val authority = authority(service, scheme)
        val request = BinaryHttpRequestTranslator.translate(raw, scheme, authority, kettled = true)
        val headers = request.fields.map { field ->
            factory.header(
                field.name().toByteArray(Charsets.ISO_8859_1),
                field.value().toByteArray(Charsets.ISO_8859_1),
            )
        }
        return factory.http2(service, headers, factory.bytes(request.body))
    }

    private fun authority(service: HttpService, scheme: String): String {
        val host = service.host().let { if (':' in it && !it.startsWith('[')) "[$it]" else it }
        val defaultPort = if (scheme == "https") 443 else 80
        return if (service.port() == defaultPort) host else "$host:${service.port()}"
    }
}
