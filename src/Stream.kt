package burp


class Stream(val connection: Connection, val streamID: Int, val req: Request, fromClient: Boolean) {

    companion object {
        const val CLEAN = 0
        const val WANTBODY = 1
        const val DONE = 2
    }

    var state = Stream.CLEAN
    var headers: String = ""
    var body: String = ""

    init {
        if (fromClient) {
//            val frame = Frame(0x04, 0x00, 0, ByteArray(0))
//            connection.sendFrame(frame)
        }
        else {
            throw Exception("Can't handle client-initiated streams yet")
        }
    }


    fun processFrame(frameBytes: ByteArray) {
        connection.stateLock.readLock().lock()
        val frame = parseFrame(frameBytes, streamID)

        Connection.debug("Stream $streamID type ${frame.type} flags ${frame.flags}")
        if (frame is SettingsFrame) {
            if (frame.maxStreams != 0) {
                // this is hard-coded instead
                if (frame.maxStreams < connection.requestsPerConnection) {
                    Connection.debug("Reducing max streams from ${connection.requestsPerConnection} to ${frame.maxStreams}")
                    connection.requestsPerConnection = frame.maxStreams
                }
            }

            // if it's not an ack, respond with an ack
            if (frame.payload.size != 0) {
                    val ackFrame = Frame(0x04, 0x01, 0, byteArrayOf())
                    connection.sendFrame(ackFrame)

            }

            // todo not sure if this should be triggered on the SETTINGS or the ACK
            connection.startSendingRequests()

            // todo in theory this is safe because... we won't get a reply
            connection.streams.remove(streamID)
            //return
        }

        if (frame is GoAwayFrame) {
            Utils.out("Server sent a GOAWAY, dumping the whole connection")
            connection.stateLock.readLock().unlock()
            connection.close()
            return
        }

        if (frame is RstStreamFrame) {
            Utils.out("Server sent a RST_STREAM, dumping the whole connection")
            connection.stateLock.readLock().unlock()
            connection.close()
            return
        }

        if (state == CLEAN) {
            if (frame is HeaderFrame) {
                headers = frame.headerString
                state = WANTBODY
            }
            else if (frame is DataFrame) {
                throw Exception("Expected headers, got data")
            }
        }
        if (state == WANTBODY) {
            if (frame is DataFrame) {
                body += frame.body

                if (connection.state == Connection.CLOSED) {
                    Utils.out("Blocked attempt to remove stream from closed connection...")
                    connection.stateLock.readLock().unlock()
                    return
                }

                if (frame.die) {
                    req.time = (System.nanoTime() - req.time) / 1000000
                    connection.engine.successfulRequests.getAndIncrement()
                    if (ThreadedRequestEngine.shouldGzip(headers)) {
                        body = ThreadedRequestEngine.decompress(body.toByteArray(Charsets.ISO_8859_1))
                    }

                    req.response = headers + "\r\n" + body
                    val interesting = connection.engine.processResponse(req, (req.response as String).toByteArray(Charsets.ISO_8859_1))
                    connection.engine.invokeCallback(req, interesting)

                    Connection.debug("Deleting stream $streamID")
                    connection.streams.remove(streamID)

                }
//                else {
//                    state = DONE
//                }
            }
        }

        connection.stateLock.readLock().unlock()
    }

    fun parseFrame(raw: ByteArray, streamID: Int): Frame {
        //Connection.debug("Raw: "+raw.asList())

        val type = raw[3]
        val flags = raw[4]
        val payload = raw.sliceArray(9..raw.size-1)

        if (streamID != HTTP2Utils.fourByteInt(raw.sliceArray(5..8))) {
            throw Exception("bad stream ID")
        }
        //val streamID = fourByteInt(raw.sliceArray(5..8))
        //Connection.debug("Type: "+type)
        //Connection.debug("Flags/Stream: $flags/$streamID")
        return when(type.toInt()) {
            0 -> DataFrame(type, flags, streamID, payload)
            1 -> HeaderFrame(type, flags, streamID, payload, this)
            3 -> RstStreamFrame(type, flags, streamID, payload)
            4 -> SettingsFrame(type, flags, streamID, payload)
            6 -> PingFrame(type, flags, streamID, payload)
            7 -> GoAwayFrame(type, flags, streamID, payload)
            8 -> WindowFrame(type, flags, streamID, payload)
            else -> Frame(type, flags, streamID, payload)
        }
    }



}
