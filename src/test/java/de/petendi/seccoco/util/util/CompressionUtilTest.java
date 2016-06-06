package de.petendi.seccoco.util.util;

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


import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.zip.GZIPInputStream;

import de.petendi.seccoco.util.CompressionUtil;


public class CompressionUtilTest {

    @Test
    public void testCompress() throws Exception {
        String testMessage = "hallo compressed";
        CompressionUtil compressionUtil = new CompressionUtil();
        byte[] compressed = compressionUtil.compress(testMessage);
        Assert.assertEquals(testMessage, decompress(compressed));
    }

    private static final String decompress(byte[] compressed) throws Exception{
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressed);
        GZIPInputStream gzipInputStream = new GZIPInputStream(byteArrayInputStream);
        return IOUtils.toString(gzipInputStream);
    }
}