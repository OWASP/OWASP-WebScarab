package javax.net.ssl;

import java.net.Socket;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

/**
 * Dummy implementation for Java 6 compatibility with Java 7 code. The methods
 * are not actually called (internally) in Java 6, just in Java 7. It is used by
 * {@code org.owasp.webscarab.httpclient.ClientTrustManager}.
 */
public abstract class X509ExtendedTrustManager implements X509TrustManager {

    public abstract void checkClientTrusted(X509Certificate[] chain,
            String authType, Socket socket) throws CertificateException;

    public abstract void checkServerTrusted(X509Certificate[] chain,
            String authType, Socket socket) throws CertificateException;

    public abstract void checkClientTrusted(X509Certificate[] chain,
            String authType, SSLEngine engine) throws CertificateException;

    public abstract void checkServerTrusted(X509Certificate[] chain,
            String authType, SSLEngine engine) throws CertificateException;
}
