fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("Not enough arguments")
        return
    }
    val proxy = Proxy("localhost", args[0].toInt())
    proxy.run()

}