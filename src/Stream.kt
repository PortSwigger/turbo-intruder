package burp


class Stream(val connection: H2Connection, val streamID: Int, val req: Request, fromClient: Boolean) {

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

        H2Connection.debug("Stream $streamID type ${frame.type} flags ${frame.flags}")
        if (frame is SettingsFrame) {
            if (frame.maxConcurrentStreams != 0) {
                // this is hard-coded instead
                H2Connection.debug("Change max concurrent streams from ${connection.requestsPerConnection} to ${frame.maxConcurrentStreams}")
                connection.maxConcurrentStreams = frame.maxConcurrentStreams
            }

            // if it's not an ack, respond with an ack
            if (frame.payload.size != 0) {
                val ackFrame = Frame(0x04, 0x01, 0, byteArrayOf())
                connection.sendFrame(ackFrame)

                // todo not sure if this should be triggered on the SETTINGS or the ACK
                 connection.startSendingRequests()
            }

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
                if (!frame.die) {
                    state = WANTBODY
                } else {
                    state = DONE
                }
            }
            else if (frame is DataFrame) {
                throw Exception("Expected headers, got data")
            }
        }

        if (state == WANTBODY) {
            if (frame is DataFrame) {
                body += frame.body
            }
        }

//        if (connection.state == Connection.CLOSED) {
//            Utils.out("Blocked attempt to remove stream from closed connection...")
//            connection.stateLock.readLock().unlock()
//            return
//        }

        if (frame.die) {
            req.time = (System.nanoTime() - req.time) / 1000000
            connection.engine.successfulRequests.getAndIncrement()
//            if (ThreadedRequestEngine.shouldUngzip(headers)) {
//                body = ThreadedRequestEngine.ungzip(body.toByteArray(Charsets.ISO_8859_1))
//            }

            req.response = headers + "\r\n" + body
            val interesting = connection.engine.processResponse(req, (req.response as String).toByteArray(Charsets.ISO_8859_1))
            connection.engine.invokeCallback(req, interesting)

            H2Connection.debug("Deleting stream $streamID")
            connection.streams.remove(streamID)

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
