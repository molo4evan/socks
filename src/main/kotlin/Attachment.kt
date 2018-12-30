import java.nio.ByteBuffer
import java.nio.channels.SelectionKey


class Attachment(var pairKey: SelectionKey?) {

    companion object {
        enum class States {
            INITIAL,
            ESTABLISH_CONNECTION,
            IN_CONNECT,
            ERROR
        }
    }

    private val bufferSize = 65536
    var input: ByteBuffer = ByteBuffer.allocate(bufferSize)
    var output: ByteBuffer = ByteBuffer.allocate(bufferSize)
    var inputIsReady: Boolean = false
    var state = States.INITIAL

    init {
        this.inputIsReady = true
    }

}