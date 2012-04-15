package org.owasp.webscarab.httpclient;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author Frank Cornelis
 */
public abstract class AbstractCertificateRepository implements CertificateRepository {

    protected Logger _logger = Logger.getLogger(getClass().getName());
    private String _defaultKey = null;
    private Map _aliasPasswords = new HashMap();
    protected List _keyStores = new ArrayList();
    protected Map _keyStoreDescriptions = new HashMap();

    public int getKeyStoreCount() {
        return _keyStores.size();
    }

    public String getKeyStoreDescription(int keystoreIndex) {
        return (String) _keyStoreDescriptions.get(_keyStores.get(keystoreIndex));
    }

    public int getAliasCount(int keystoreIndex) {
        return getAliases((KeyStore) _keyStores.get(keystoreIndex)).length;
    }

    public String getAliasAt(int keystoreIndex, int aliasIndex) {
        return getAliases((KeyStore) _keyStores.get(keystoreIndex))[aliasIndex];
    }

    private String[] getAliases(KeyStore ks) {
        List aliases = new ArrayList();
        try {
            Enumeration en = ks.aliases();
            while (en.hasMoreElements()) {
                String alias = (String) en.nextElement();
                if (ks.isKeyEntry(alias)) {
                    aliases.add(alias);
                }
            }
        } catch (KeyStoreException kse) {
            kse.printStackTrace();
        }
        return (String[]) aliases.toArray(new String[0]);
    }

    public Certificate getCertificate(int keystoreIndex, int aliasIndex) {
        try {
            KeyStore ks = (KeyStore) _keyStores.get(keystoreIndex);
            String alias = getAliasAt(keystoreIndex, aliasIndex);
            return ks.getCertificate(alias);
        } catch (Exception e) {
            return null;
        }
    }

    public String getFingerPrint(Certificate cert) throws KeyStoreException {
        if (!(cert instanceof X509Certificate)) {
            return null;
        }
        StringBuffer buff = new StringBuffer();
        X509Certificate x509 = (X509Certificate) cert;
        try {
            String fingerprint = Encoding.hashMD5(cert.getEncoded());
            for (int i = 0; i < fingerprint.length(); i += 2) {
                buff.append(fingerprint.substring(i, i + 1)).append(":");
            }
            buff.deleteCharAt(buff.length() - 1);
        } catch (CertificateEncodingException e) {
            throw new KeyStoreException(e.getMessage());
        }
        String dn = x509.getSubjectDN().getName();
        _logger.info("Fingerprint is " + buff.toString().toUpperCase());
        return buff.toString().toUpperCase() + " " + dn;
    }

    public boolean isProviderAvailable(String type) {
        try {
            if (type.equals("PKCS11")) {
                Class.forName("sun.security.pkcs11.SunPKCS11");
            }
        } catch (Throwable t) {
            return false;
        }
        return true;
    }

    public boolean isKeyUnlocked(int keystoreIndex, int aliasIndex) {
        KeyStore ks = (KeyStore) _keyStores.get(keystoreIndex);
        String alias = getAliasAt(keystoreIndex, aliasIndex);

        Map pwmap = (Map) _aliasPasswords.get(ks);
        if (pwmap == null) {
            return false;
        }
        return pwmap.containsKey(alias);
    }

    public void setDefaultKey(String fingerprint) {
        _defaultKey = fingerprint;
    }

    public String getDefaultKey() {
        return _defaultKey;
    }

    private int addKeyStore(KeyStore ks, String description) {
        int index = _keyStores.indexOf(ks);
        if (index == -1) {
            _keyStores.add(ks);
            index = _keyStores.size() - 1;
        }
        _keyStoreDescriptions.put(ks, description);
        return index;
    }

    public int initPKCS11(String name, String library, int slotListIndex, String kspassword) {
        try {
            if (!isProviderAvailable("PKCS11")) {
                return -1;
            }

            // Set up a virtual config file
            StringBuffer cardConfig = new StringBuffer();
            cardConfig.append("name = ").append(name).append("\n");
            cardConfig.append("library = ").append(library).append("\n");
            cardConfig.append("slotListIndex = ").append(Integer.toString(slotListIndex)).append("\n");
            InputStream is = new ByteArrayInputStream(cardConfig.toString().getBytes());

            // create the provider
            Class pkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
            Constructor c = pkcs11Class.getConstructor(new Class[]{InputStream.class});
            Provider pkcs11 = (Provider) c.newInstance(new Object[]{is});
            Security.addProvider(pkcs11);

            // init the key store
            KeyStore ks = KeyStore.getInstance("PKCS11");
            ks.load(null, kspassword == null ? null : kspassword.toCharArray());
            return addKeyStore(ks, name);
        } catch (Exception e) {
            System.err.println("Error instantiating the PKCS11 provider");
            e.printStackTrace();
            return -1;
        }
    }

    public int loadPKCS12Certificate(String filename, String ksPassword)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        // Open the file
        InputStream is = new FileInputStream(filename);

        // create the keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(is, ksPassword == null ? null : ksPassword.toCharArray());
        return addKeyStore(ks, "PKCS#12 - " + filename);
    }
}
