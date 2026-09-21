package http3

import hp3.h3.Http3Request

data class TurboHttp3Request(
    val request: Http3Request,
    val authoredVersion: String,
)
