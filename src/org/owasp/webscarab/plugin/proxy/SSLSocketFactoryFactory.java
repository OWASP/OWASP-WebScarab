package org.owasp.webscarab.plugin.proxy;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import org.owasp.webscarab.util.SunCertificateUtils;

public class SSLSocketFactoryFactory {

	/* set the date of issue to one month ago */
	private static final long DEFAULT_AGE = 30L * 24L * 60L * 60L * 1000L;
	private static final long DEFAULT_VALIDITY = 10L * 365L * 24L * 60L * 60L
			* 1000L;

	private static Logger logger = Logger
			.getLogger(SSLSocketFactoryFactory.class.getName());

	private static final String CA = "CA";

	private static X500Principal CA_NAME;

	static {
		try {
			CA_NAME = new X500Principal("cn=OWASP Custom CA for "
					+ java.net.InetAddress.getLocalHost().getHostName()
					+ " at " + new Date()
					+ ",ou=OWASP Custom CA,o=OWASP,l=OWASP,st=OWASP,c=OWASP");
		} catch (IOException ioe) {
			ioe.printStackTrace();
			CA_NAME = null;
		}
	}

	private PrivateKey caKey;

	private X509Certificate[] caCerts;

	private String filename;

	private KeyStore keystore;

	private char[] password;

	private boolean reuseKeys = false;

	private Map<String, SSLContext> contextCache = new HashMap<String, SSLContext>();

	private Set<BigInteger> serials = new HashSet<BigInteger>();

	public SSLSocketFactoryFactory() throws GeneralSecurityException,
			IOException, OperatorCreationException {
		this(null, "JKS", "password".toCharArray());
	}

	public SSLSocketFactoryFactory(String filename, String type, char[] password)
			throws GeneralSecurityException, IOException, OperatorCreationException {
		this(filename, type, password, CA_NAME);
	}

	public SSLSocketFactoryFactory(String filename, String type,
			char[] password, X500Principal caName)
			throws GeneralSecurityException, IOException, OperatorCreationException {
		this.filename = filename;
		this.password = password;
		keystore = KeyStore.getInstance(type);
		File file = new File(filename);
		if (filename == null) {
			logger
					.info("No keystore provided, keys and certificates will be transient!");
		}
		if (file.exists()) {
			logger.fine("Loading keys from " + filename);
			InputStream is = new FileInputStream(file);
			keystore.load(is, password);
			caKey = (PrivateKey) keystore.getKey(CA, password);
			if (caKey == null) {
				logger.warning("Keystore does not contain an entry for '" + CA
						+ "'");
			}
			caCerts = cast(keystore.getCertificateChain(CA));
			initSerials();
		} else {
			logger.info("Generating CA key");
			keystore.load(null, password);
			generateCA(caName);
		}
	}

	/**
	 * Determines whether the public and private key generated for the CA will
	 * be reused for other hosts as well.
	 * 
	 * This is mostly just a performance optimisation, to save time generating a
	 * key pair for each host. Paranoid clients may have an issue with this, in
	 * theory.
	 * 
	 * @param reuse
	 *            true to reuse the CA key pair, false to generate a new key
	 *            pair for each host
	 */
	public void setReuseKeys(boolean reuse) {
		reuseKeys = reuse;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.CertificateProvider#getSocketFactory(java.lang
	 * .String, int)
	 */
	public synchronized SSLSocketFactory getSocketFactory(String host,
		X509Certificate baseCrt)
			throws IOException, GeneralSecurityException,
                        OperatorCreationException {
		SSLContext sslcontext = contextCache.get(host);
		if (sslcontext == null) {
			X509KeyManager km;
			if (!keystore.containsAlias(host)) {
				km = createKeyMaterial(host, baseCrt);
			} else {
				km = loadKeyMaterial(host);
			}
			sslcontext = SSLContext.getInstance("TLSv1");
			sslcontext.init(new KeyManager[] { km }, null, null);
			contextCache.put(host, sslcontext);
		}
		return sslcontext.getSocketFactory();
	}

	private X509Certificate[] cast(Certificate[] chain) {
		X509Certificate[] certs = new X509Certificate[chain.length];
		for (int i = 0; i < chain.length; i++) {
			certs[i] = (X509Certificate) chain[i];
		}
		return certs;
	}
	
	private X509KeyManager loadKeyMaterial(String host)
                throws GeneralSecurityException, IOException {
		X509Certificate[] certs = null;
		Certificate[] chain = keystore.getCertificateChain(host);
		if (chain != null) {
			certs = cast(chain);
		} else {
			throw new GeneralSecurityException(
					"Internal error: certificate chain for " + host
							+ " not found!");
		}

		PrivateKey pk = (PrivateKey) keystore.getKey(host, password);
		if (pk == null) {
			throw new GeneralSecurityException(
					"Internal error: private key for " + host + " not found!");
		}
		return new HostKeyManager(host, pk, certs);
	}

	private void saveKeystore() {
		if (filename == null)
			return;
		try {
			OutputStream out = new FileOutputStream(filename);
			keystore.store(out, password);
			out.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		}
	}

	private void generateCA(X500Principal caName)
			throws GeneralSecurityException, IOException,
                        OperatorCreationException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair caPair = keyGen.generateKeyPair();
		caKey = caPair.getPrivate();
		PublicKey caPubKey = caPair.getPublic();
		Date begin = new Date();
		begin.setTime(begin.getTime() - DEFAULT_AGE);
		Date ends = new Date(begin.getTime() + DEFAULT_VALIDITY);

		X509Certificate cert = SunCertificateUtils.sign(caName, caPubKey,
				caName, caPubKey, caKey, begin, ends, BigInteger.ONE,
                                null);
		caCerts = new X509Certificate[] { cert };

		keystore.setKeyEntry(CA, caKey, password, caCerts);
		saveKeystore();
	}

	private void initSerials() throws GeneralSecurityException {
		Enumeration<String> e = keystore.aliases();
		while (e.hasMoreElements()) {
			String alias = e.nextElement();
			X509Certificate cert = (X509Certificate) keystore
					.getCertificate(alias);
			BigInteger serial = cert.getSerialNumber();
			serials.add(serial);
		}
	}

	protected X500Principal getSubjectPrincipal(String host) {
		return new X500Principal("cn=" + host + ",ou=UNTRUSTED,o=UNTRUSTED");
	}

	protected BigInteger getNextSerialNo() {
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		while (serials.contains(serial))
			serial.add(BigInteger.ONE);
		serials.add(serial);
		return serial;
	}

	private X509KeyManager createKeyMaterial(String host, X509Certificate baseCrt)
			throws GeneralSecurityException, IOException, OperatorCreationException {
		KeyPair keyPair;

		if (reuseKeys) {
			keyPair = new KeyPair(caCerts[0].getPublicKey(), caKey);
		} else {
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
			keygen.initialize(1024);
			keyPair = keygen.generateKeyPair();
		}

		X500Principal subject = getSubjectPrincipal(host);
		Date begin = new Date();
		begin.setTime(begin.getTime() - DEFAULT_AGE);
		Date ends = new Date(begin.getTime() + DEFAULT_VALIDITY);

		X509Certificate cert = SunCertificateUtils.sign(subject, keyPair
				.getPublic(), caCerts[0].getSubjectX500Principal(), caCerts[0]
				.getPublicKey(), caKey, begin, ends, getNextSerialNo(),
				baseCrt);

		X509Certificate[] chain = new X509Certificate[caCerts.length + 1];
		System.arraycopy(caCerts, 0, chain, 1, caCerts.length);
		chain[0] = cert;

		PrivateKey pk = keyPair.getPrivate();

		keystore.setKeyEntry(host, pk, password, chain);
		saveKeystore();
		return new HostKeyManager(host, pk, chain);
	}

	private class HostKeyManager implements X509KeyManager {

		private String host;

		private PrivateKey pk;

		private X509Certificate[] certs;

		public HostKeyManager(String host, PrivateKey pk,
				X509Certificate[] certs) {
			this.host = host;
			this.pk = pk;
			this.certs = certs;
		}

		public String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			throw new UnsupportedOperationException("Not implemented");
		}

		public String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
			return host;
		}

		public X509Certificate[] getCertificateChain(String alias) {
			return certs;
		}

		public String[] getClientAliases(String keyType, Principal[] issuers) {
			throw new UnsupportedOperationException("Not implemented");
		}

		public PrivateKey getPrivateKey(String alias) {
			return pk;
		}

		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return new String[] { host };
		}

	}

}
