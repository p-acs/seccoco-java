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


import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import de.petendi.seccoco.connector.BCConnector;
import de.petendi.seccoco.model.Identity;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;

import de.petendi.commons.crypto.Certificates;
import de.petendi.commons.crypto.HybridCrypto;
import de.petendi.commons.crypto.model.HybridEncrypted;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultIOTest {
    private SecurityProviderConnector securityProviderConnector = new BCConnector();

    @Test
    public void testDispatch() throws Exception {
        final String serialized = "testString";
        HybridCrypto hybridCrypto = new HybridCrypto(securityProviderConnector);
        Certificates certificates = new Certificates(securityProviderConnector);
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        final String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        hybridCrypto.addRecipient(id, stringReader);
        HybridEncrypted hybridEncrypted = hybridCrypto.build(serialized.getBytes(), password, new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        DefaultIdentities defaultIdentitiesMock = mock(DefaultIdentities.class);
        Identity ownIdentity = new Identity(cert,id);
        when(defaultIdentitiesMock.getOwnIdentity()).thenReturn(ownIdentity);
        char[] appSecret = RandomStringUtils.randomAlphanumeric(20).toCharArray();
        DefaultCrypto defaultCrypto = new DefaultCrypto(password, byteArrayOutputStream.toByteArray(), defaultIdentitiesMock, appSecret, ownIdentity);
        when(defaultIdentitiesMock.isSignatureValid(any(Identity.class), any(byte[].class), any(byte[].class))).thenReturn(true);
        DefaultIO defaultIO = new DefaultIO(defaultIdentitiesMock, defaultCrypto, appSecret);
        final String response = "response";
        HybridEncrypted responseObject = DefaultCrypto.toHybridEncrypted(defaultIO.dispatch(id, DefaultCrypto.toEncryptedMessage(hybridEncrypted), new IO.UnencryptedResponse() {
            @Override
            public byte[] getUnencryptedResponse(byte[] bytes, String identity, String certificate) {
                assertEquals(id, identity);
                assertArrayEquals(serialized.getBytes(), bytes);
                assertEquals(cert, certificate);
                return response.getBytes();
            }
        }));
        HybridCrypto hybridCrypto1 = new HybridCrypto(securityProviderConnector);

        byte[] decResponse = hybridCrypto1.decrypt(responseObject, id, password, new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        assertArrayEquals(response.getBytes(), decResponse);
    }
}