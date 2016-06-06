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


import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import de.petendi.seccoco.argument.ArgumentList;

import static org.mockito.Mockito.mock;

/**
 *
 */
public class SeccocoFactoryTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testInitialStart() {
        ArgumentList argumentList = new ArgumentList();
        argumentList.setUserDirectory(folder.getRoot().getAbsolutePath());
        SeccocoFactory seccocoFactory = new SeccocoFactory("seccoco", argumentList);
        Seccoco result = seccocoFactory.create();
        String testText = "TEST";
        byte[] encrypted = result.crypto().encrypt(testText.getBytes());
        String testDecrypted = new String(result.crypto().decrypt(encrypted));
        Assert.assertEquals(testText, testDecrypted);
    }

    @Test
    public void testApplicationPasswordIntegrity() {
        ArgumentList argumentList = new ArgumentList();
        argumentList.setUserDirectory(folder.getRoot().getAbsolutePath());
        final StringBuilder passwordHolder = new StringBuilder();
        SeccocoFactory.OutputWriter outputWriter = new SeccocoFactory.OutputWriter() {
            @Override
            public void println(String message) {
                final String prefix = "Application password: ";
                if (message.startsWith(prefix)) {
                    passwordHolder.append(message.replace(prefix, ""));
                }
            }
        };
        SeccocoFactory initialSeccocoFactory = new SeccocoFactory("seccoco", argumentList, outputWriter);
        Seccoco result = initialSeccocoFactory.create();
        ArgumentList argumentListWithPassword = new ArgumentList();
        argumentListWithPassword.setUserDirectory(folder.getRoot().getAbsolutePath());
        argumentListWithPassword.setTokenPassword(passwordHolder.toString().toCharArray());
        SeccocoFactory initializedSeccocoFactory = new SeccocoFactory("seccoco", argumentListWithPassword);
        String testText = "TEST";
        byte[] encrypted = result.crypto().encrypt(testText.getBytes());
        Seccoco restoredResult = initializedSeccocoFactory.create();
        String testDecrypted = new String(restoredResult.crypto().decrypt(encrypted));
        Assert.assertEquals(testText, testDecrypted);
    }
}
