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

import de.petendi.commons.crypto.SymmetricCrypto;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import de.petendi.seccoco.connector.BCConnector;

import java.io.ByteArrayInputStream;
import java.io.StringReader;

import de.petendi.commons.crypto.HybridCrypto;
import de.petendi.commons.crypto.model.HybridEncrypted;
import de.petendi.seccoco.model.EncryptedMessage;
import de.petendi.seccoco.model.Identity;

class DefaultCrypto implements Crypto{
    private DefaultIdentities defaultIdentities;
    private char[] password;
    private byte[] pkcs12;
    private final char[] appSecret;
    private final Identity ownIdentity;
    private SecurityProviderConnector securityProviderConnector = new BCConnector();

    DefaultCrypto(char[] password, byte[] pkcs12, DefaultIdentities defaultIdentities, char[] appSecret, Identity ownIdentity) {
        this.password = password;
        this.pkcs12 = pkcs12;
        this.defaultIdentities = defaultIdentities;
        this.appSecret = appSecret;
        this.ownIdentity = ownIdentity;
    }

    @Override
    public EncryptedMessage encrypt(byte[] message, Identity identity) {
        HybridCrypto hybridCrypto = new HybridCrypto(securityProviderConnector);
        hybridCrypto.addRecipient(identity.getFingerPrint(), new StringReader(identity.getCertificate()));
        return toEncryptedMessage(hybridCrypto.build(message, password, new ByteArrayInputStream(pkcs12)));
    }

    @Override
    public EncryptedMessage encryptForSelf(byte[] message) {
        return encrypt(message,ownIdentity);
    }

    @Override
    public byte[] decrypt(EncryptedMessage message) {
        HybridCrypto crypto = new HybridCrypto(securityProviderConnector);
        return crypto.decrypt(toHybridEncrypted(message), defaultIdentities.getOwnIdentity().getFingerPrint(), password, new ByteArrayInputStream(pkcs12));
    }

    @Override
    public byte[] encrypt(byte[] plain) {
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        return symmetricCrypto.encrypt(plain, appSecret);
    }

    @Override
    public byte[] decrypt(byte[] encrypted) {
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        return symmetricCrypto.decrypt(encrypted, appSecret);
    }

    static HybridEncrypted toHybridEncrypted(EncryptedMessage encryptedMessage) {
        HybridEncrypted hybridEncrypted = new HybridEncrypted();
        hybridEncrypted.setCertificates(encryptedMessage.getCertificates());
        hybridEncrypted.setEncryptedBody(encryptedMessage.getEncryptedBody());
        hybridEncrypted.setHeaders(encryptedMessage.getHeaders());
        hybridEncrypted.setSignature(encryptedMessage.getSignature());
        hybridEncrypted.setRecipients(encryptedMessage.getRecipients());
        return hybridEncrypted;
    }

    static EncryptedMessage toEncryptedMessage(HybridEncrypted hybridEncrypted) {
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setCertificates(hybridEncrypted.getCertificates());
        encryptedMessage.setEncryptedBody(hybridEncrypted.getEncryptedBody());
        encryptedMessage.setHeaders(hybridEncrypted.getHeaders());
        encryptedMessage.setSignature(hybridEncrypted.getSignature());
        encryptedMessage.setRecipients(hybridEncrypted.getRecipients());
        return encryptedMessage;
    }
}
