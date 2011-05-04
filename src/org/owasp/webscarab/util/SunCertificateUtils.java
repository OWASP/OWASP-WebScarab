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

package org.owasp.webscarab.util;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

public class SunCertificateUtils {

    private static final String SIGALG = "SHA1withRSA";

    public static X509Certificate sign(X500Principal subject, PublicKey pubKey,
            X500Principal issuer, PublicKey caPubKey, PrivateKey caKey,
            Date begin, Date ends, BigInteger serialNo)
            throws GeneralSecurityException {

        X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.reset();
        certificateGenerator.setPublicKey(pubKey);
        certificateGenerator.setSignatureAlgorithm(SIGALG);
        certificateGenerator.setNotBefore(begin);
        certificateGenerator.setNotAfter(ends);
        certificateGenerator.setIssuerDN(issuer);
        certificateGenerator.setSubjectDN(subject);
        certificateGenerator.setSerialNumber(serialNo);

        if (subject.equals(issuer)) {
            certificateGenerator.addExtension(
                    X509Extensions.BasicConstraints, true,
                    new BasicConstraints(5));
        } else {
            SubjectKeyIdentifierStructure subjectKeyIdentifier = new SubjectKeyIdentifierStructure(pubKey);
            certificateGenerator.addExtension(
                    X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);

            AuthorityKeyIdentifierStructure authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(caPubKey);
            certificateGenerator.addExtension(
                    X509Extensions.AuthorityKeyIdentifier, false,
                    authorityKeyIdentifier);

            certificateGenerator.addExtension(
                    X509Extensions.BasicConstraints, true,
                    new BasicConstraints(false));

            NetscapeCertType netscapeCertType = new NetscapeCertType(NetscapeCertType.sslClient | NetscapeCertType.sslServer);
            certificateGenerator.addExtension(
                    MiscObjectIdentifiers.netscapeCertType, false,
                    netscapeCertType);

            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            certificateGenerator.addExtension(X509Extensions.KeyUsage, true,
                    keyUsage);

            Vector keyPurposeIds = new Vector();
            keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
            keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds);
            certificateGenerator.addExtension(X509Extensions.ExtendedKeyUsage, false,
                    extendedKeyUsage);
        }

        X509Certificate certificate = certificateGenerator.generate(caKey);
        /*
         * Next certificate factory trick is needed to make sure that the
         * certificate delivered to the caller is provided by the default
         * security provider instead of BouncyCastle. If we don't do this trick
         * we might run into trouble when trying to use the CertPath validator.
         */
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
        return certificate;
    }
}
