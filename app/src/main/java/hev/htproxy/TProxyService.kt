package hev.htproxy

/**
 * JNI-обёртка hev-socks5-tunnel (AAR из релизов heiher/hev-socks5-tunnel).
 * Нативные методы регистрируются на hev.htproxy.TProxyService.
 */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    private external fun TProxyStartService(configPath: String, fd: Int): Boolean
    private external fun TProxyStopService(): Boolean
    private external fun TProxyIsRunning(): Boolean
    private external fun TProxyGetStats(): LongArray

    fun start(cfgPath: String, fd: Int): Boolean = TProxyStartService(cfgPath, fd)
    fun stop(): Boolean = TProxyStopService()
    fun isRunning(): Boolean = TProxyIsRunning()
}
