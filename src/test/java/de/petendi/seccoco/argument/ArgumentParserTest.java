package de.petendi.seccoco.argument;

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

import java.io.File;
import java.io.IOException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 *
 */
public class ArgumentParserTest {



    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testArgumentsOK() throws IOException {
        String pw = "123";
        String cmdLine = "-wd %1$2s -pw %2$2s -token %3$2s";
        File testCert =  folder.newFile("testCert.p12");
        String[] args = String.format(cmdLine,folder.getRoot(),pw,testCert.getAbsolutePath()).split(" ");
        ArgumentList argumentList = new ArgumentParser(folder.getRoot().getAbsolutePath(),args).getArgumentList();
        Assert.assertArrayEquals(pw.toCharArray(),argumentList.getTokenPassword());
        Assert.assertEquals(testCert.getAbsolutePath(),argumentList.getToken().getAbsolutePath());
        Assert.assertEquals(folder.getRoot().getAbsolutePath(),argumentList.getWorkingDirectory().getAbsolutePath());
    }
    @Test
    public void testArgumentsOKRelativePath() throws IOException {
        String pw = "123";
        String cmdLine = "-wd %1$2s -pw %2$2s -token %3$2s";
        File testCert =  folder.newFile("testCert.p12");
        String[] args = String.format(cmdLine,folder.getRoot(),pw,testCert.getName()).split(" ");
        ArgumentList argumentList = new ArgumentParser(folder.getRoot().getAbsolutePath(),args).getArgumentList();
        Assert.assertArrayEquals(pw.toCharArray(),argumentList.getTokenPassword());
        Assert.assertEquals(testCert.getAbsolutePath(),argumentList.getToken().getAbsolutePath());
        Assert.assertEquals(folder.getRoot().getAbsolutePath(),argumentList.getWorkingDirectory().getAbsolutePath());
    }

    @Test(expected = ArgumentParseException.class)
    public void testArgumentsErrorRelativePathWithoutWorkingdirectory() throws IOException {
        String pw = "123";
        String cmdLine = "-pw %1$2s -token %2$2s";
        File testCert =  folder.newFile("testCert.p12");
        String[] args = String.format(cmdLine,pw,testCert.getName()).split(" ");
        new ArgumentParser(folder.getRoot().getAbsolutePath(),args).getArgumentList();
    }

    @Test(expected = ArgumentParseException.class)
    public void testParseError() throws IOException {
        String cmdLine = "---";
        String[] args = cmdLine.split(" ");
        new ArgumentParser(folder.getRoot().getAbsolutePath(),args).getArgumentList();
    }

    @Test(expected = HelpTextRequestedException.class)
    public void testShowHelp() throws IOException {
        String cmdLine = "-h";
        String[] args = cmdLine.split(" ");
        new ArgumentParser(folder.getRoot().getAbsolutePath(),args).getArgumentList();

    }
}
