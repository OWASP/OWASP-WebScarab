package org.owasp.webscarab.util;

/**
 * Provides a method of interacting with the Windows WinInet utility DLL.
 * This is obviously only interesting on a MS Windows platform. Most usefully, it
 * provides JNI methods of getting and setting the Internet Explorer proxy settings,
 * in such a way that the changes affect all existing running instances of Internet Explorer immediately,
 * and the user does NOT need to exit the browser for the changes to be effective.
 */
public class W32WinInet {

    /**
     * Specifies that some connections may be made directly to the server, bypassing the proxy
     */    
    public static int PROXY_TYPE_DIRECT         = 0x00000001;   // direct to net
    /**
     * Specifies that some connections may go via a proxy
     */    
    public static int PROXY_TYPE_PROXY          = 0x00000002;   // via named proxy
    /**
     * Not sure exactly what this one does. Maybe that a .pac file is active?
     */    
    public static int PROXY_TYPE_AUTO_PROXY_URL = 0x00000004;   // autoproxy URL
    /**
     * Specifies that the browser will auto detect the proxy, according to the MS auto-detect methodology
     */    
    public static int PROXY_TYPE_AUTO_DETECT    = 0x00000008;   // use autoproxy detection

    private static boolean _available = false;
    
    private static boolean _intercepted = false;
    private static long _perConn = 0;
    private static String _proxyServer = null;
    private static String _proxyBypass = null;
    
    private native static int testLibraryLoad();
    
    private native static long getInternetPerConnFlags();
    
    private native static long getAutoDiscoveryFlags();

    private native static String getAutoConfigUrl();

    private native static String getProxyServer();

    private native static String getProxyBypass();

    private native static int setProxy(long perConnFlags, String proxyServer, String proxyBypass);

    static {
        try {
            System.loadLibrary("W32WinInet");
            if (testLibraryLoad() == 1) 
                _available = true;
        } catch (UnsatisfiedLinkError ule) {
            _available = false;
        }
    }
    
    /**
     * Allows the caller to test whether the native library was successfully loaded.
     * @return true if the native library was successfully loaded, false otherwise
     */    
    public static boolean isAvailable() {
        return _available;
    }
    
    /**
     * Causes the existing WinInet proxy settings to be saved, and the new proxy settings supplied to be configured
     * This sets the proxy for ALL services, and ensures that ALL connections go through the supplied proxy, including
     * connections to local servers.
     * @param server the name or address of the proxy server
     * @param port the port of the proxy server
     * @return true if the settings were successfully replaced, false otherwise
     */    
    public static boolean interceptProxy(String server, int port) {
        if (!isAvailable()) return false;
        if (! _intercepted) {
            _perConn = getInternetPerConnFlags();
            _proxyServer = getProxyServer();
            _proxyBypass = getProxyBypass();
        }
        int result = setProxy(PROXY_TYPE_PROXY, server + ":" + port, null);
        if (result != 0) {
            result = setProxy(_perConn, _proxyServer, _proxyBypass);
            return false;
        }
        _intercepted = true;
        return true;
    }
    
    /**
     * resets the WinInet proxy settings to their original values
     */    
    public static void revertProxy() {
        if (! _intercepted) return;
        int result = setProxy(_perConn, _proxyServer, _proxyBypass);
        _intercepted = false;
    }
    
    private static String getProxy(String type) {
        String proxy;
        if (_intercepted) {
            proxy = _proxyServer;
        } else {
            proxy = getProxyServer();
        }
        if (proxy == null) return null;
        String[] proxies;
        if (proxy.indexOf("=")>0) {
            proxies = proxy.split(";");
        } else {
            return proxy;
        }
        for (int i=0; i<proxies.length; i++) {
            if (proxies[i].startsWith(type+"=")) {
                return proxies[i].substring(proxies[i].indexOf("=")+1);
            }
        }
        return null;
    }
    
    /**
     * gets the name or address of the original WinInet HTTP proxy server, regardless of
     * any intercepts that may have been made.
     * @return the name or address of the WinInet proxy server
     */    
    public static String getHttpProxyServer() {
        String proxy = getProxy("http");
        if (proxy == null) return null;
        return proxy.substring(0, proxy.indexOf(":"));
    }
    
    /**
     * gets the port of the original WinInet HTTP proxy server, regardless of
     * any intercepts that may have been made.
     * @return the port of the WinInet proxy server, or -1 if none is configured or there is an error parsing the port number
     */
    public static int getHttpProxyPort() {
        String proxy = getProxy("http");
        if (proxy == null) return -1;
        try {
            return Integer.parseInt(proxy.substring(proxy.indexOf(":")+1));
        } catch (NumberFormatException nfe) {
            return -1;
        }
    }
    
    /**
     * gets the name or address of the original WinInet HTTPS proxy server, regardless of
     * any intercepts that may have been made.
     * @return the name or address of the WinInet proxy server
     */
    public static String getHttpsProxyServer() {
        String proxy = getProxy("https");
        if (proxy == null) return null;
        return proxy.substring(0, proxy.indexOf(":"));
    }
    
    /**
     * gets the port of the original WinInet HTTPS proxy server, regardless of
     * any intercepts that may have been made.
     * @return the port of the WinInet proxy server, or -1 if none is configured or there is an error parsing the port number
     */
    public static int getHttpsProxyPort() {
        String proxy = getProxy("https");
        if (proxy == null) return -1;
        try {
            return Integer.parseInt(proxy.substring(proxy.indexOf(":")+1));
        } catch (NumberFormatException nfe) {
            return -1;
        }
    }
    
    /**
     * returns the original WinInet list of hosts or addresses that should be
     * connected to directly, rather than using the proxy.
     * @return a semi-colon separated list of hosts or addresses
     */    
    public static String getNoProxy() {
        String bypass;
        if (!_intercepted) {
            bypass = getProxyBypass();
        } else {
            bypass = _proxyBypass;
        }
        if (bypass == null) return null;
        return bypass;
    }
    
    public static void main(String[] args) throws Exception {
        if (!isAvailable()) {
            System.err.println("DLL not found, or wrong platform!");
            System.exit(1);
        }
        if (args.length == 0) {
            System.err.println("Please specify an address to set temporarily");
            System.err.println("e.g. W32WinInet localhost:3128");
        }
        long perConn = getInternetPerConnFlags();
        String proxyServer = getProxyServer();
        String proxyBypass = getProxyBypass();
        
        System.out.println("Current settings:");
        System.out.println("PerConnFlags: " + perConn);
        System.out.println("ProxyServer: " + proxyServer);
        System.out.println("ProxyBypass: " + proxyBypass);
        System.out.println();
        
        System.out.println("Changed to " + args[0] + ", result is : " + setProxy(PROXY_TYPE_PROXY, args[0], null));
        
        System.out.println("Settings are now:");
        System.out.println("PerConnFlags: " + getInternetPerConnFlags());
        System.out.println("ProxyServer: " + getProxyServer());
        System.out.println("ProxyBypass: " + getProxyBypass());
        
        System.out.print("Press enter to change them back: ");
        System.in.read();
        
        System.out.println("Result is : " + setProxy(perConn, proxyServer, proxyBypass));
        System.out.println();

        System.out.println("Current settings:");
        System.out.println("PerConnFlags: " + getInternetPerConnFlags());
        System.out.println("ProxyServer: " + getProxyServer());
        System.out.println("ProxyBypass: " + getProxyBypass());
        
    }
}

