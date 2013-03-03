/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 Frank Cornelis <info@frankcornelis.be>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */
package test.unit.org.owasp.webscarab.util;

import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.bouncycastle.asn1.DERBitString;
import org.apache.commons.logging.Log;
import java.util.Date;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.junit.Test;
import org.owasp.webscarab.util.SunCertificateUtils;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

/**
 *
 * @author Frank Cornelis
 */
public class SunCertificateUtilsTest {

    private static final Log LOG = LogFactory.getLog(SunCertificateUtilsTest.class);

    @Test
    public void testSign() throws Exception {
        // setup
        KeyPair caKeyPair = generateKeyPair();
        KeyPair entityKeyPair = generateKeyPair();
        X500Principal subject = new X500Principal("CN=Test");
        PublicKey pubKey = entityKeyPair.getPublic();
        X500Principal issuer = new X500Principal("CN=CA");
        PublicKey caPubKey = caKeyPair.getPublic();
        PrivateKey caKey = caKeyPair.getPrivate();
        Date begin = new Date();
        Date ends = new Date(begin.getTime() + (long) 1000 * 60 * 60 * 24 * 30);
        BigInteger serialNo = BigInteger.valueOf(1234);
        JcaX509ExtensionUtils jxeu = new JcaX509ExtensionUtils();

        // operate
        X509Certificate resultCert = SunCertificateUtils.sign(subject, pubKey, issuer, caPubKey, caKey, begin, ends, serialNo, null);

        // verify
        assertNotNull(resultCert);
        LOG.debug("result certificate: " + resultCert);
        resultCert.verify(caPubKey);
        assertEquals(subject, resultCert.getSubjectX500Principal());
        assertEquals(issuer, resultCert.getIssuerX500Principal());
        assertEquals(serialNo, resultCert.getSerialNumber());
        assertEquals(pubKey, resultCert.getPublicKey());
        LOG.debug("expected begin: " + begin.getTime());
        LOG.debug("actual begin: " + resultCert.getNotBefore().getTime());
        /*
         * BouncyCastle drops the milliseconds.
         */
        assertTrue(Math.abs(begin.getTime() - resultCert.getNotBefore().getTime()) < 1000);
        assertTrue(Math.abs(ends.getTime() - resultCert.getNotAfter().getTime()) < 1000);

        byte[] subjectKeyIdentifierExtValue = resultCert.getExtensionValue(X509Extension.subjectKeyIdentifier.getId());
        assertNotNull(subjectKeyIdentifierExtValue);
        ASN1Primitive subjectKeyIdentifier = JcaX509ExtensionUtils.parseExtensionValue(
                subjectKeyIdentifierExtValue);
        ASN1Primitive expSKI = jxeu.createSubjectKeyIdentifier(pubKey).toASN1Primitive();
        assertArrayEquals(expSKI.getEncoded(), subjectKeyIdentifier.getEncoded());

        byte[] authorityKeyIdentifierExtValue = resultCert.getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
        ASN1Primitive authorityKeyIdentifier = JcaX509ExtensionUtils.parseExtensionValue(
                authorityKeyIdentifierExtValue);
        ASN1Primitive expAKI = jxeu.createAuthorityKeyIdentifier(caPubKey).toASN1Primitive();
        assertArrayEquals(expAKI.getEncoded(), authorityKeyIdentifier.getEncoded());

        assertEquals(-1, resultCert.getBasicConstraints());

        byte[] netscapeCertTypeExtValue = resultCert.getExtensionValue(MiscObjectIdentifiers.netscapeCertType.getId());
        assertNotNull(netscapeCertTypeExtValue);
        DERBitString netscapeCertTypeExt = (DERBitString) X509ExtensionUtil.fromExtensionValue(netscapeCertTypeExtValue);
        NetscapeCertType netscapeCertType = new NetscapeCertType(netscapeCertTypeExt);
        assertEquals(NetscapeCertType.sslClient, netscapeCertType.intValue() & NetscapeCertType.sslClient);
        assertEquals(NetscapeCertType.sslServer, netscapeCertType.intValue() & NetscapeCertType.sslServer);

        assertTrue(resultCert.getKeyUsage()[0]);
        assertTrue(resultCert.getKeyUsage()[2]);

        byte[] extendedKeyUsageExtValue = resultCert.getExtensionValue(X509Extension.extendedKeyUsage.getId());
        assertNotNull(extendedKeyUsageExtValue);
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(X509ExtensionUtil.fromExtensionValue(extendedKeyUsageExtValue));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
    }

    private KeyPair generateKeyPair(int size) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(size,
                RSAKeyGenParameterSpec.F4), random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPair keyPair = generateKeyPair(1024);
        return keyPair;
    }
}
