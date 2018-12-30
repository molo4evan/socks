import org.xbill.DNS.*
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel

class Proxy(
    private val lhost: String,
    private val lport: Int
) {

    private val selector = Selector.open()
    private val listener = ServerSocketChannel.open()
    private val resolver = SimpleResolver()

    companion object {
        const val socksVersion: Byte = 0x05
        const val authenticationMethod: Byte = 0x00
        const val unsupportedMethod: Byte = 0xFF.toByte()
        const val establishTCPStreamConnection: Byte = 0x01
        const val IPv4Address: Byte = 0x01
        const val domain: Byte = 0x03
        const val reserved: Byte = 0x00

        enum class Error(val type: Byte, val decriprion: String) {
            REQUEST_GRANTED(0x00, "REQUEST_GRANTED"),
            GENERAL_FAILURE(0x01, "GENERAL_FAILURE"),
            CONNECTION_NOT_ALLOWED(0x02, "CONNECTION_NOT_ALLOWED"),
            NETWORK_UNREACHABLE(0x03, "NETWORK_UNREACHABLE"),
            HOST_UNREACHABLE(0x04, "HOST_UNREACHABLE"),
            CONNECTION_REFUSED(0x05, "CONNECTION_REFUSED"),
            TTL_EXPIRED(0x06, "TTL_EXPIRED"),
            COMMAND_NOT_SUPPORTED(0x07, "COMMAND_NOT_SUPPORTED"),
            PROTOCOL_ERROR(0x07, "PROTOCOL_ERROR"),
            UNSUPPORTED_ADDRESS_TYPE(0x08, "UNSUPPORTED_ADDRESS_TYPE")
        }
    }

    init {
        resolver.setAddress(InetAddress.getByName("8.8.8.8"))   //TODO: mb try use config resolver?
    }

    fun run(): Nothing {

        listener.bind(InetSocketAddress(lhost, lport))
        listener.configureBlocking(false)
        listener.register(selector, SelectionKey.OP_ACCEPT)

        while (true) {
            val num = selector.select()
            if (num == 0) {
                continue
            }

            val keys = selector.selectedKeys()
            val it = keys.iterator()
            while (it.hasNext()) {
                val key = it.next() as SelectionKey
                if (key.isValid) {
                    when {
                        key.isAcceptable -> {
                            accept()
                        }
                        key.isConnectable -> {
                            connect(key)
                        }
                        key.isReadable -> {
                            read(key)
                        }
                        key.isWritable -> {
                            write(key)
                        }
                    }
                }
            }
            keys.clear()
        }
    }

    private fun accept() {
        val client = listener.accept() ?: return
        client.configureBlocking(false)
        val clientKey = client.register(selector, SelectionKey.OP_READ)
        println("Client key = $clientKey")
        val clientAttachment = Attachment(null)
        clientKey.attach(clientAttachment)
    }

    private fun read(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        val attachment = key.attachment() as Attachment
        println("Read from $key")
        attachment.input.clear()
        val readBufferCount = try{
            channel.read(attachment.input)
        } catch (ex: IOException){
            close(key)
            return
        }
        if (readBufferCount > 1) {
            println("Red $readBufferCount from $key")
            attachment.input.flip()
            when {
                attachment.state == Attachment.Companion.States.INITIAL -> {
                    establishConnection(key, attachment)
                }

                attachment.state == Attachment.Companion.States.ESTABLISH_CONNECTION -> {
                    connectToServer(key, attachment)
                }

                attachment.state == Attachment.Companion.States.IN_CONNECT -> {
                    if (attachment.pairKey == null) {
                        close(key)
                        return
                    }
                    val ops = attachment.pairKey!!.interestOps()
                    attachment.pairKey?.interestOps(ops or SelectionKey.OP_WRITE)
                    key.interestOps(key.interestOps() xor SelectionKey.OP_READ)
                }
            }
        } else {
            close(key)
        }
    }

    private fun connect(key: SelectionKey) {
        println("Connecting to key $key")
        val channel = key.channel() as SocketChannel
        if (key.attachment() == null) {
            close(key)
            return
        }
        val attachment = key.attachment() as Attachment
        if (attachment.pairKey == null){
            close(key)
            return
        }
        if (channel.finishConnect()) {
            attachment.output = (attachment.pairKey!!.attachment() as Attachment).input
            (attachment.pairKey!!.attachment() as Attachment).output = attachment.input
            key.interestOps(SelectionKey.OP_READ)
            val address = ByteBuffer.allocate(Int.SIZE_BYTES)
            address.put(0)
            address.put(0)
            address.put(0)
            address.put(0)
            val a = makeConnectAnswer(Error.REQUEST_GRANTED, IPv4Address, address.array(), 0)
            (attachment.pairKey?.attachment() as Attachment).output
                .put(a)
            (attachment.pairKey?.attachment() as Attachment).output.flip()
            attachment.pairKey?.interestOps(SelectionKey.OP_WRITE)
        } else {
            close(key)
        }
    }

    private fun write(key: SelectionKey) {
        println("Perform write to $key")
        val channel = key.channel() as SocketChannel
        val attachment = key.attachment() as Attachment
        val writeBufferCount = try {
            channel.write(attachment.output)
        } catch (ex: IOException) {
            close(key)
            return
        }
        if (writeBufferCount > 0) {
            print("Wrote $writeBufferCount for $key")
            if (!attachment.output.hasRemaining()) {
                attachment.output.compact()
                key.interestOps(SelectionKey.OP_READ)
                when (attachment.state) {
                    Attachment.Companion.States.ERROR -> {
                        close(key)
                        return
                    }
                    Attachment.Companion.States.INITIAL -> {
                        attachment.state = Attachment.Companion.States.ESTABLISH_CONNECTION
                        println(": first header")
                        return
                    }
                    Attachment.Companion.States.ESTABLISH_CONNECTION -> {
                        attachment.state = Attachment.Companion.States.IN_CONNECT
                        println(": second header")
                        return
                    }
                    Attachment.Companion.States.IN_CONNECT -> {
                        println(": in connect")
                        if (attachment.pairKey == null) {
                            close(key)
                            return
                        } else {
                            attachment.output.clear()
                            val ops = attachment.pairKey?.interestOps() ?: throw Exception("Null pairKey for $key")
                            attachment.pairKey?.interestOps(ops or SelectionKey.OP_READ)
                            return
                        }
                    }
                }
            }
        } else {
            close(key)
        }
    }

    private fun close(key: SelectionKey) {
        println("Close key $key")
        key.channel().close()
        key.cancel()
        val pairKey = (key.attachment() as Attachment).pairKey
        if (pairKey != null) {
            (pairKey.attachment() as Attachment).pairKey = null
        }
    }

    private fun establishConnection(key: SelectionKey, attachment: Attachment) {
        val clientSocksVersion = attachment.input.get()
        val clientAuthMethodCount = attachment.input.get()
        val clientAuthMethods = getClientAuthMethods(clientAuthMethodCount, attachment.input)
        print("Red from client $key first header: $clientSocksVersion|$clientAuthMethodCount|")
        for (elem in clientAuthMethods) {
            print("$elem,")
        }
        println()
        print("Make answer for client $key first header: ")
        attachment.output.clear()
        if ((clientSocksVersion != socksVersion) || (!clientAuthMethods.contains(authenticationMethod))) {
            attachment.output.put(makeHelloAnswer(unsupportedMethod))
            attachment.state = Attachment.Companion.States.ERROR
        } else {
            attachment.output.put(makeHelloAnswer(authenticationMethod))
        }
        key.interestOps(SelectionKey.OP_WRITE)
        attachment.output.flip()
    }

    private fun connectToServer(key: SelectionKey, attachment: Attachment) {
        val clientSocksVersion = attachment.input.get()
        val requestCommand = attachment.input.get()
        val reserve = attachment.input.get()
        val addressType = attachment.input.get()
        val address =
            when (addressType) {
                IPv4Address -> {
                    val buffer = ByteArray(Int.SIZE_BYTES)
                    attachment.input.get(buffer, 0, Int.SIZE_BYTES)
                    buffer
                }
                domain -> {
                    val domainLength = attachment.input.get().toInt()
                    val buffer = ByteArray(domainLength)
                    attachment.input.get(buffer, 0, domainLength)
                    buffer
                }
                else -> {
                    val count = attachment.input.capacity() - attachment.input.position() - Char.SIZE_BYTES
                    val buffer = ByteArray(count)
                    attachment.input.get(buffer, 0, count)
                    buffer
                }
            }
        val port = attachment.input.short
        println("Red from client $key second header: $clientSocksVersion|$requestCommand|$reserve|$addressType|$address|$port")

        if (requestCommand != establishTCPStreamConnection) {
            attachment.output.put(makeConnectAnswer(Error.COMMAND_NOT_SUPPORTED, addressType, address, port))
            attachment.state = Attachment.Companion.States.ERROR
            key.interestOps(SelectionKey.OP_WRITE)
            System.err.println("Red UNSUPPORTED_COMMAND from $key")
        } else if ((clientSocksVersion != socksVersion) || (reserve != reserved)) {
            attachment.output.put(makeConnectAnswer(Error.PROTOCOL_ERROR, addressType, address, port))
            attachment.state = Attachment.Companion.States.ERROR
            key.interestOps(SelectionKey.OP_WRITE)
            System.err.println("Red PROTOCOL_ERROR from $key")
        } else if (addressType == IPv4Address) {
            attachment.pairKey = makeServerChannel(key, InetAddress.getByAddress(address), port.toInt())
        } else if (addressType == domain) {
            val msg = Message()
            msg.header.opcode = Opcode.QUERY
            val fullDomain = String(address) + "."
            println("FULL DOMAIN IS $fullDomain")
            msg.addRecord(Record.newRecord(Name(fullDomain), Type.A, DClass.IN), Section.QUESTION)
            resolver.sendAsync(msg, object : ResolverListener{
                override fun handleException(id: Any?, e: java.lang.Exception?) {
                    e?.printStackTrace() ?: println("GOT NULL EXCEPTION")
                }

                override fun receiveMessage(id: Any?, m: Message?) {
                    if (m == null) {
                        println("GOT NULL MESSAGE")
                        return
                    }

                    println("GOT MESSAGE")
                    println()

                    val answer = m.getSectionArray(Section.ANSWER)
                    for (record in answer) {
                        println(record)
                        if (record is ARecord){
                            println("FOUND ADDRESS ${record.address}")
                            attachment.pairKey = makeServerChannel(key, record.address, port.toInt())
                            key.interestOps(key.interestOps() xor SelectionKey.OP_READ)
                            attachment.output.flip()
                            return
                        }
                    }
                    println("NO ADDRESS SPECIFIED")

                    val sect = m.getSectionArray(Section.AUTHORITY)
                    println("AUTHORITY")
                    for (rec in sect){
                        println(rec)
                        val ns = rec as NSRecord
                    }

                    attachment.output.put(makeConnectAnswer(Error.HOST_UNREACHABLE, addressType, address, port))
                    attachment.state = Attachment.Companion.States.ERROR
                    key.interestOps(SelectionKey.OP_WRITE)
                }
            })
            key.interestOps(0)
            return
        } else {
            attachment.output.put(makeConnectAnswer(Error.UNSUPPORTED_ADDRESS_TYPE, addressType, address, port))
            attachment.state = Attachment.Companion.States.ERROR
            key.interestOps(SelectionKey.OP_WRITE)
            System.err.println("Red UNSUPPORTED_ADDRESS_TYPE from $key")
        }
        key.interestOps(key.interestOps() xor SelectionKey.OP_READ)
        attachment.output.flip()
    }

    private fun makeHelloAnswer(authMethod: Byte): ByteArray {
        val answer = ByteArray(2)
        answer[0] = socksVersion
        answer[1] = authMethod
        println("$socksVersion|$authMethod")
        return answer
    }

    private fun getClientAuthMethods(count: Byte, methodsBuffer: ByteBuffer): ArrayList<Byte> {
        val methods = ArrayList<Byte>()
        for (i in 0 until count) {
            methods.add(methodsBuffer.get())
        }
        return methods
    }

    private fun makeConnectAnswer(status: Error, addressType: Byte, address: ByteArray, port: Short): ByteBuffer {
        val capacity = Byte.SIZE_BYTES * 4 +
                if (addressType == IPv4Address) {
                    Int.SIZE_BYTES
                } else {
                    address.size
                } + Short.SIZE_BYTES
        val answer = ByteBuffer.allocate(capacity)
        answer.put(socksVersion)
        answer.put(status.type)
        answer.put(reserved)
        answer.put(addressType)
        answer.put(address)
        answer.putShort(port)
        answer.flip()
        return answer
    }

    private fun makeServerChannel(clientKey: SelectionKey, host: InetAddress, port: Int): SelectionKey {
        val server = SocketChannel.open()
        server.configureBlocking(false)
        server.connect(InetSocketAddress(host, port))
        val serverKey = server.register(selector, SelectionKey.OP_CONNECT)
        val serverAttachment = Attachment(clientKey)
        serverAttachment.state = Attachment.Companion.States.IN_CONNECT
        serverKey.attach(serverAttachment)
        return serverKey
    }

}