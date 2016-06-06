package de.petendi.seccoco.connector;

/*-
 * #%L
 * Seccoco Java
 * %%
 * Copyright (C) 2016 P-ACS UG (haftungsbeschränkt)
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */


import de.petendi.commons.crypto.connector.CryptoException;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class BCConnector implements SecurityProviderConnector {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public BCConnector() {
    }

    @Override
    public X509Certificate createCertificate(String dn, String issuer, String crlUri,
                                             PublicKey publicKey, PrivateKey privateKey) throws CryptoException {
        Calendar date = Calendar.getInstance();
        // Serial Number
        BigInteger serialNumber = BigInteger
                .valueOf(date.getTimeInMillis());
        // Subject and Issuer DN
        X500Name subjectDN = new X500Name(dn);
        X500Name issuerDN = new X500Name(issuer);
        // Validity
        Date notBefore = date.getTime();
        date.add(Calendar.YEAR, 20);
        Date notAfter = date.getTime();
        // SubjectPublicKeyInfo
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(
                ASN1Sequence.getInstance(publicKey.getEncoded()));

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuerDN, serialNumber, notBefore, notAfter, subjectDN,
                subjPubKeyInfo);
        DigestCalculator digCalc = null;
        try {
            digCalc = new BcDigestCalculatorProvider()
                    .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
            X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);
            // Subject Key Identifier
            certGen.addExtension(Extension.subjectKeyIdentifier, false,
                    x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));
            // Authority Key Identifier
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));
            // Key Usage
            certGen.addExtension(Extension.keyUsage, false, new KeyUsage(
                    KeyUsage.dataEncipherment));
            if (crlUri != null) {
                // CRL Distribution Points
                DistributionPointName distPointOne = new DistributionPointName(
                        new GeneralNames(new GeneralName(
                                GeneralName.uniformResourceIdentifier,
                                crlUri)));

                DistributionPoint[] distPoints = new DistributionPoint[1];
                distPoints[0] = new DistributionPoint(distPointOne, null, null);
                certGen.addExtension(Extension.cRLDistributionPoints, false,
                        new CRLDistPoint(distPoints));
            }

            // Content Signer
            ContentSigner sigGen = new JcaContentSignerBuilder(
                    getSignAlgorithm()).setProvider(getProviderName()).build(privateKey);
            // Certificate
            return new JcaX509CertificateConverter()
                    .setProvider(getProviderName()).getCertificate(certGen.build(sigGen));
        } catch (Exception e) {
            throw new CryptoException(e);
        }

    }

    @Override
    public void writeCertificate(Writer pemWriter, X509Certificate selfCert) throws IOException {
        JcaPEMWriter certWriter = new JcaPEMWriter(pemWriter);
        certWriter.writeObject(selfCert);
        certWriter.flush();
        certWriter.close();
    }

    @Override
    public byte[] hash(byte[] input) {
        SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
        md.update(input);
        return md.digest();
    }

    @Override
    public final PublicKey extractPublicKey(Reader pemReader) throws CryptoException {
        return extractCertificate(pemReader).getPublicKey();
    }

    @Override
    public X509Certificate extractCertificate(Reader pemReader) throws CryptoException {

        try {
            PEMParser parser = new PEMParser(pemReader);
            Object object = parser.readObject();
            pemReader.close();
            parser.close();
            if (object instanceof X509CertificateHolder) {
                X509CertificateHolder x509Holder = (X509CertificateHolder) object;
                return new JcaX509CertificateConverter().setProvider(getProviderName())
                        .getCertificate(x509Holder);
            } else {
                throw new IllegalArgumentException("no certificate found in pem");
            }
        } catch (IOException e) {
            throw new CryptoException(e);
        } catch (CertificateException e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String getProviderName() {
        return "BC";
    }

    @Override
    public String getCryptoAlgorithm() {
        return "RSA/ECB/PKCS1Padding";
    }

    @Override
    public String getSignAlgorithm() {
        return "SHA1WithRSA";
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public SecretKey generateSecretKey() {
        final int outputKeyLength = 256;
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        keyGenerator.init(outputKeyLength, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    @Override
    public byte[] base64Encode(byte[] bytes) {
        return Base64.encode(bytes);
    }

    @Override
    public byte[] base64Decode(byte[] bytes) {
        return Base64.decode(bytes);
    }


}