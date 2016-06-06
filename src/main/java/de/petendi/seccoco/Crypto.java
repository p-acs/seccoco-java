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

public interface Crypto {
    EncryptedMessage encrypt(byte[] message, Identity identity);

    EncryptedMessage encryptForSelf(byte[] message);

    byte[] decrypt(EncryptedMessage message);

    byte[] encrypt(byte[] plain);

    byte[] decrypt(byte[] encrypted);
}
