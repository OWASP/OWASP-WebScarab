package org.owasp.webscarab.httpclient;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 *
 * @author Frank Cornelis
 */
public interface CertificateRepository {

    boolean isProviderAvailable(String type);

    void setDefaultKey(String fingerprint);

    Certificate getCertificate(int keystoreIndex, int aliasIndex);

    boolean isKeyUnlocked(int keystoreIndex, int aliasIndex);

    void unlockKey(int keystoreIndex, int aliasIndex, String keyPassword) throws KeyStoreException, KeyManagementException;

    String getFingerPrint(Certificate cert) throws KeyStoreException;

    int loadPKCS12Certificate(String filename, String ksPassword)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException;

    String getKeyStoreDescription(int keystoreIndex);

    int initPKCS11(String name, String library, int slotListIndex, String kspassword);

    int getKeyStoreCount();

    int getAliasCount(int keystoreIndex);

    String getAliasAt(int keystoreIndex, int aliasIndex);
}
