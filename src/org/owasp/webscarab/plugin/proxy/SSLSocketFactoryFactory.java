package org.owasp.webscarab.plugin.proxy;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class SSLSocketFactoryFactory {

	private static Logger logger = Logger
			.getLogger(SSLSocketFactoryFactory.class.getName());

	private static final String CA = "CA";

	private static final String SIGALG = "SHA1withRSA";

	private static X500Name CA_NAME;

	static {
		try {
			CA_NAME = new X500Name("OWASP Custom CA", "OWASP Custom CA", "OWASP", "OWASP",
					"OWASP", "OWASP");
		} catch (IOException ioe) {
			ioe.printStackTrace();
			CA_NAME = null;
		}
	}

	private String filename;

	private KeyStore keystore;

	private char[] password;

	private boolean reuseKeys = false;

	private Map contextCache = new HashMap();

	private X500Name caName;

	public SSLSocketFactoryFactory() throws GeneralSecurityException,
			IOException {
		this(null, "JKS", "password".toCharArray());
	}

	public SSLSocketFactoryFactory(String filename, String type, char[] password)
			throws GeneralSecurityException, IOException {
		this(filename, type, password, CA_NAME);
	}

	public SSLSocketFactoryFactory(String filename, String type,
			char[] password, X500Name caName) throws GeneralSecurityException,
			IOException {
		this.filename = filename;
		this.password = password;
		this.caName = caName;
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
			if (keystore.getKey(CA, password) == null) {
				logger.warning("Keystore does not contain an entry for '" + CA
						+ "'");
			}
		} else {
			logger.info("Generating CA key");
			keystore.load(null, password);
			generateCA();
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
	public synchronized SSLSocketFactory getSocketFactory(String host)
			throws IOException, GeneralSecurityException {
		SSLContext sslcontext = (SSLContext) contextCache.get(host);
		if (sslcontext == null) {
			if (!keystore.containsAlias(host))
				generate(host, reuseKeys);
			sslcontext = SSLContext.getInstance("SSLv3");
			HostKeyManager km = new HostKeyManager(host);
			sslcontext.init(new KeyManager[] { km }, null, null);
			contextCache.put(host, sslcontext);
		}
		return sslcontext.getSocketFactory();
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

	private void generateCA() throws GeneralSecurityException, IOException {
		CertAndKeyGen keygen = new CertAndKeyGen("RSA", SIGALG);
		keygen.generate(1024);

		PrivateKey key = keygen.getPrivateKey();

		java.security.cert.X509Certificate certificate = keygen
				.getSelfCertificate(caName, 10L * 365L * 24L * 60L * 60L);

		certificate.checkValidity();
		keystore.setKeyEntry(CA, key, password,
				new Certificate[] { certificate });
		saveKeystore();
	}

	private void generate(String cname, boolean reuseKeys)
			throws GeneralSecurityException {
		try {
			PrivateKey caKey = (PrivateKey) keystore.getKey(CA, password);
			PublicKey caPubKey = keystore.getCertificate(CA).getPublicKey();
			Certificate[] caCertChain = keystore.getCertificateChain(CA);
			X509Certificate caCert = (X509Certificate) caCertChain[0];

			PrivateKey privKey = caKey;
			PublicKey pubKey = caPubKey;

			if (!reuseKeys) {
				CertAndKeyGen keygen = new CertAndKeyGen("RSA", SIGALG);
				keygen.generate(1024);
				privKey = keygen.getPrivateKey();
				pubKey = keygen.getPublicKey();
			}

			Signature signature = Signature.getInstance(SIGALG);

			signature.initSign(caKey);
			X500Signer issuer = new X500Signer(signature, caName);

			Date begin = new Date();
			Date ends = caCert.getNotAfter();
			CertificateValidity valid = new CertificateValidity(begin, ends);
			X500Name subject = new X500Name(cname, caName
					.getOrganizationalUnit(), caName.getOrganization(), caName
					.getCountry());

			X509CertInfo info = new X509CertInfo();
			// Add all mandatory attributes
			info.set(X509CertInfo.VERSION, new CertificateVersion(
					CertificateVersion.V3));
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
					(int) (begin.getTime() / 1000)));
			AlgorithmId algID = issuer.getAlgorithmId();
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(
					algID));
			info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
			info.set(X509CertInfo.KEY, new CertificateX509Key(pubKey));
			info.set(X509CertInfo.VALIDITY, valid);
			info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer
					.getSigner()));

			X509CertImpl cert = new X509CertImpl(info);
			cert.sign(caKey, SIGALG);

			Certificate[] certChain = new Certificate[caCertChain.length + 1];
			System.arraycopy(caCertChain, 0, certChain, 1, caCertChain.length);
			certChain[0] = cert;

			keystore.setKeyEntry(cname, privKey, password, certChain);

			saveKeystore();
		} catch (IOException e) {
			CertificateEncodingException cee = new CertificateEncodingException(
					"generate: " + e.getMessage());
			cee.initCause(e);
			throw cee;
		}
	}

	private class HostKeyManager implements X509KeyManager {

		private String host;

		private PrivateKey pk;

		private X509Certificate[] certs;

		public HostKeyManager(String host) throws GeneralSecurityException {
			this.host = host;
			Certificate[] chain = keystore.getCertificateChain(host);
			if (chain != null) {
				certs = new X509Certificate[chain.length];
				for (int i = 0; i < chain.length; i++) {
					certs[i] = (X509Certificate) chain[i];
				}
			} else {
				throw new GeneralSecurityException(
						"Internal error: certificate chain for " + host
								+ " not found!");
			}

			pk = (PrivateKey) keystore.getKey(host, password);
			if (pk == null) {
				throw new GeneralSecurityException(
						"Internal error: private key for " + host
								+ " not found!");
			}
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
