package org.owasp.webscarab.httpclient;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * A trust manager implementation that assumes that the world is not evil, that
 * no government is spying on you: it simply accepts all certificates regardless
 * of the contents of the certificate (algorithm, CN, ...).
 */
public class ClientTrustManager extends X509ExtendedTrustManager
        implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] xcs, String string)
            throws CertificateException {
        // trust all certificates
    }

    @Override
    public void checkServerTrusted(X509Certificate[] xcs, String string)
            throws CertificateException {
        // trust all certificates
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] xcs, String string,
            Socket socket) throws CertificateException {
        // trust any client-supplied certificate
    }

    @Override
    public void checkServerTrusted(X509Certificate[] xcs, String string,
            Socket socket) throws CertificateException {
        // trust all
    }

    @Override
    public void checkClientTrusted(X509Certificate[] xcs, String string,
            SSLEngine ssle) throws CertificateException {
        // trust all
    }

    @Override
    public void checkServerTrusted(X509Certificate[] xcs, String string,
            SSLEngine ssle) throws CertificateException {
        // trust all
    }
}
