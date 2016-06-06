package de.petendi.seccoco.model;

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

import java.util.Map;

public class EncryptedMessage {
    private byte[] encryptedBody = null;
    private Map<String,String> headers = null;
    private Map<String,byte[]> recipients = null;
    private Map<String,String> certificates = null;
    private byte[] signature = null;

    public byte[] getEncryptedBody() {
        return encryptedBody;
    }
    public void setEncryptedBody(byte[] encryptedBody) {
        this.encryptedBody = encryptedBody;
    }
    public Map<String, String> getHeaders() {
        return headers;
    }
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }
    public Map<String, byte[]> getRecipients() {
        return recipients;
    }
    public void setRecipients(Map<String, byte[]> recipients) {
        this.recipients = recipients;
    }

    public Map<String, String> getCertificates() {
        return certificates;
    }

    public void setCertificates(Map<String, String> certificates) {
        this.certificates = certificates;
    }

    public byte[] getSignature() {
        return signature;
    }
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}
