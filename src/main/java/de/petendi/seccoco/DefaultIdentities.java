package de.petendi.seccoco;

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
import de.petendi.seccoco.connector.BCConnector;
import de.petendi.seccoco.model.Identity;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import de.petendi.commons.crypto.Signature;


class DefaultIdentities implements Identities {
    private static final String SUFFIX = ".pem";
    private File certDirectory;
    private final Identity ownIdentity;
    private BCConnector securityProviderConnector = new BCConnector();

    DefaultIdentities(File certDirectory, Identity ownIdentity) {
        this.ownIdentity = ownIdentity;
        this.certDirectory = certDirectory;
        certDirectory.mkdirs();
    }

    @Override
    public boolean store(Identity identity) {
        if (containsCertificate(identity.getCertificate())) {
            File certificate = new File(certDirectory, identity.getFingerPrint() + SUFFIX);
            boolean certificateExisted = certificate.exists();
            if (!certificateExisted) {
                FileWriter writer = null;
                try {
                    writer = new FileWriter(certificate);
                    IOUtils.write(identity.getCertificate(), writer);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                } finally {
                    IOUtils.closeQuietly(writer);
                }
            }
            return certificateExisted;
        } else {
            throw new CertificateCorruptedException();
        }
    }

    boolean containsCertificate(String certificate) {
        Signature signatureTool = new Signature(securityProviderConnector);
        return signatureTool.containsPublicKey(new StringReader(certificate));
    }


    @Override
    public Identity extractFromPem(Reader pemReader) {
        try {
            String certificate = IOUtils.toString(pemReader);
            X509Certificate x509Certificate = securityProviderConnector.extractCertificate(new StringReader(certificate));
            return new Identity(certificate, extractFingerPrint(x509Certificate));
        } catch (Exception e) {
            throw new IllegalArgumentException("could not extract certificate", e);
        }
    }

    @Override
    public Identity getOwnIdentity() {
        return ownIdentity;
    }

    @Override
    public Identity get(String fingerprint) {
        File certificate = new File(certDirectory, fingerprint + SUFFIX);
        try {
            Signature signatureTool = new Signature(securityProviderConnector);
            FileReader certificateReader = new FileReader(certificate);
            boolean containsPublicKey = signatureTool.containsPublicKey(certificateReader);
            IOUtils.closeQuietly(certificateReader);
            certificateReader = new FileReader(certificate);
            if (containsPublicKey) {
                return extractFromPem(certificateReader);
            } else {
                IOUtils.closeQuietly(certificateReader);
                throw new CertificateNotFoundException();
            }
        } catch (FileNotFoundException e) {
            throw new CertificateNotFoundException();
        }
    }

    boolean isSignatureValid(Identity identity, byte[] signature, byte[] input) {
        Signature signatureTool = new Signature(securityProviderConnector);
        try {
            return signatureTool.verify(input, signature, securityProviderConnector.extractPublicKey(new StringReader(identity.getCertificate())));
        } catch (CryptoException e) {
            return false;
        }
    }

    boolean isSignatureValid(String fingerprint, byte[] signature, byte[] input) {
        return isSignatureValid(get(fingerprint), signature, input);
    }


    static String extractFingerPrint(X509Certificate certificate) throws CertificateEncodingException {
        return new String(Hex.encodeHex(DigestUtils.sha1(certificate.getEncoded())));
    }

    class CertificateNotFoundException extends RuntimeException {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

    }

    class CertificateCorruptedException extends RuntimeException {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

    }

}
