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


import de.petendi.seccoco.model.EncryptedMessage;
import de.petendi.seccoco.model.Identity;
import org.cryptonode.jncryptor.AES256JNCryptorInputStream;
import org.cryptonode.jncryptor.AES256JNCryptorOutputStream;
import org.cryptonode.jncryptor.CryptorException;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;


class DefaultIO implements IO{

    private final DefaultIdentities defaultIdentities;
    private final Crypto defaultCrypto;
    private final char[] appSecret;

    public DefaultIO(DefaultIdentities defaultIdentities, DefaultCrypto defaultCrypto, char[] appSecret) {
        this.defaultIdentities = defaultIdentities;
        this.defaultCrypto = defaultCrypto;
        this.appSecret = appSecret;
    }

    @Override
    public EncryptedMessage dispatch(String identity, EncryptedMessage encryptedMessage, IO.UnencryptedResponse response) throws IO.RequestException {
        return dispatch(identity, encryptedMessage, response,false);
    }

    @Override
    public EncryptedMessage dispatch(String identity, EncryptedMessage encryptedMessage, IO.UnencryptedResponse response, boolean restrictToLocalCertificates) throws IO.RequestException {
        byte[] signature = encryptedMessage.getSignature();
        byte[] input = encryptedMessage.getEncryptedBody();
        boolean signatureValid;
        String certificate = null;
        boolean messageHasCertificate = false;
        if (encryptedMessage.getCertificates() != null) {
            String certFromMessage =  encryptedMessage.getCertificates().get(identity);
            if(!restrictToLocalCertificates) {
                certificate = certFromMessage;
                messageHasCertificate = certificate!=null;
            }
        }
        if (certificate != null) {
            Identity identityObj = new Identity(certificate,identity);
            signatureValid = defaultIdentities.isSignatureValid(identityObj, signature, input);
        } else {
            try {
                signatureValid = defaultIdentities.isSignatureValid(identity, signature, input);
            } catch (DefaultIdentities.CertificateNotFoundException e) {
                if(messageHasCertificate) {
                    throw new CertificateNotAcceptedException();
                } else {
                    throw new CertificateNotFoundException();
                }
            }
        }

        if (signatureValid) {
            byte[] bytes = defaultCrypto.decrypt(encryptedMessage);
            return getEncryptedResponse(bytes, identity, certificate, response);
        } else {
            throw new SignatureCheckFailedException();
        }
    }


    @Override
    public OutputStream encrypt(OutputStream plainOutputStream, int mode) throws FileNotFoundException {
        try {
            return new AES256JNCryptorOutputStream(plainOutputStream,appSecret);
        } catch (CryptorException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public InputStream decrypt(InputStream encryptedInputStream) throws FileNotFoundException {
        return new AES256JNCryptorInputStream(encryptedInputStream,appSecret);
    }

    private EncryptedMessage getEncryptedResponse(byte[] unencryptedRequest, String identity, String certificate, IO.UnencryptedResponse response) throws IO.RequestException {
        try {
            byte[] result = response.getUnencryptedResponse(unencryptedRequest, identity, certificate);
            EncryptedMessage hybridEncrypted;
            Identity identityObj;
            if (certificate == null) {
                identityObj = defaultIdentities.get(identity);

            } else {
                identityObj = new Identity(certificate,identity);
            }
            hybridEncrypted = defaultCrypto.encrypt(result, identityObj);
            return hybridEncrypted;
        } catch (Exception e) {
            throw new InvalidInputException();
        }
    }
}
