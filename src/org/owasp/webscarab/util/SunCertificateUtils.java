/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 Frank Cornelis <info@frankcornelis.be>
 *               2013 Peter Wu <lekensteyn@gmail.com>
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
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class SunCertificateUtils {

    private static final String SIGALG = "SHA1withRSA";

    public static X509Certificate sign(X500Principal subject, PublicKey pubKey,
            X500Principal issuer, PublicKey caPubKey, PrivateKey caKey,
            Date begin, Date ends, BigInteger serialNo,
            X509Certificate baseCrt)
            throws GeneralSecurityException, CertIOException, OperatorCreationException, IOException {

        if (baseCrt != null) {
            subject = baseCrt.getSubjectX500Principal();
        }

        JcaX509v3CertificateBuilder certificateBuilder;
        certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNo,
                begin, ends, subject, pubKey);

        if (subject.equals(issuer)) {
            certificateBuilder.addExtension(
                    X509Extension.basicConstraints, true,
                    new BasicConstraints(5));
        } else {
            JcaX509ExtensionUtils jxeu = new JcaX509ExtensionUtils();

            if (baseCrt != null) {
                byte[] sans = baseCrt.getExtensionValue(X509Extension.subjectAlternativeName.getId());
                if (sans != null) {
                    certificateBuilder.copyAndAddExtension(X509Extension.subjectAlternativeName, true, baseCrt);
                }
            }

            SubjectKeyIdentifier subjectKeyIdentifier = jxeu.createSubjectKeyIdentifier(pubKey);
            certificateBuilder.addExtension(
                    X509Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

            AuthorityKeyIdentifier authorityKeyIdentifier = jxeu.createAuthorityKeyIdentifier(caPubKey);
            certificateBuilder.addExtension(
                    X509Extension.authorityKeyIdentifier, false,
                    authorityKeyIdentifier);

            certificateBuilder.addExtension(
                    X509Extension.basicConstraints, true,
                    new BasicConstraints(false));

            NetscapeCertType netscapeCertType = new NetscapeCertType(NetscapeCertType.sslClient | NetscapeCertType.sslServer);
            certificateBuilder.addExtension(
                    MiscObjectIdentifiers.netscapeCertType, false,
                    netscapeCertType);

            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            certificateBuilder.addExtension(X509Extension.keyUsage, true,
                    keyUsage);

            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[]{
                KeyPurposeId.id_kp_clientAuth,
                KeyPurposeId.id_kp_serverAuth
            });
            certificateBuilder.addExtension(X509Extension.extendedKeyUsage, false,
                    extendedKeyUsage);
        }

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGALG);
        X509CertificateHolder holder = certificateBuilder.build(signerBuilder.build(caKey));

        /*
         * Next certificate factory trick is needed to make sure that the
         * certificate delivered to the caller is provided by the default
         * security provider instead of BouncyCastle. If we don't do this trick
         * we might run into trouble when trying to use the CertPath validator.
         */
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
        return certificate;
    }
}
