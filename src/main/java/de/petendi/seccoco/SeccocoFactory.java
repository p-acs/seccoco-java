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
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.util.Properties;

import de.petendi.commons.crypto.AsymmetricCrypto;
import de.petendi.commons.crypto.Certificates;
import de.petendi.seccoco.argument.ArgumentList;
import org.bouncycastle.util.encoders.Base64;

public class SeccocoFactory {

    private final ArgumentList argumentList;
    private final String componentName;
    private final OutputWriter outputWriter;
    private BCConnector securityProviderConnector = new BCConnector();
    public SeccocoFactory(String componentName, ArgumentList argumentList) {
        this(componentName, argumentList, new OutputWriter() {
            @Override
            public void println(String message) {
                System.out.println(message);
            }
        });
    }

    public SeccocoFactory(String componentName, ArgumentList argumentList,OutputWriter outputWriter) {
        this.componentName = componentName;
        this.argumentList = argumentList;
        this.outputWriter = outputWriter;
    }

    public Seccoco create() {

        File certFile = argumentList.getToken();
        File workingDirectory = argumentList.getWorkingDirectory();
        if (workingDirectory == null) {
            workingDirectory = new File(argumentList.getUserDirectory());
            if (!workingDirectory.isDirectory()) {
                throw new InitializationException("userdirectory not a directory - set proper user.dir environment or a valid workingdirectory");
            }
        }
        if (!workingDirectory.canWrite()) {
            throw new InitializationException("workingdirectory is not writable");
        }
        workingDirectory = new File(workingDirectory, componentName);
        if (!workingDirectory.exists()) {
            if (!workingDirectory.mkdirs()) {
                throw new InitializationException("Creating of working directory failed");
            }
        }
        argumentList.setWorkingDirectory(workingDirectory);

        out("Using workingdirectory " + workingDirectory.getAbsolutePath());
        boolean noPublicKeyAvailable = true;
        File publicKeyFile = new File(workingDirectory, "public.pem");
        noPublicKeyAvailable = !publicKeyFile.exists();
        char[] password = argumentList.getTokenPassword();
        if (certFile == null) {
            out("No certfile given as argument, looking it up");
            File defaultTokenFile = new File(workingDirectory, "cert.p12");
            if (defaultTokenFile.exists()) {
                out("Found certificate under defaultpath " + defaultTokenFile.getAbsolutePath());
                certFile = defaultTokenFile;
            } else {
                out("No certificate found under defaultpath " + defaultTokenFile.getAbsolutePath());
                if (noPublicKeyAvailable) {
                    if (password.length == 0) {
                        out("No password given as argument, creating a random password");
                        String randomPw = RandomStringUtils.randomAlphanumeric(20);
                        out("IMPORTANT: remember this password well! Without that password you will not be able to start the application again!");
                        out("----------");
                        out("Application password: " + randomPw);
                        out("----------");
                        password = randomPw.toCharArray();

                    }
                    if (createSelfSignedCertificate(workingDirectory, password, defaultTokenFile)) {
                        certFile = defaultTokenFile;
                    } else {
                        throw new InitializationException("error creating selfsigned certificate");
                    }
                } else {
                    throw new InitializationException("public key available, but no private key");
                }
            }
        }

        //at this point either a selfsigned certificate was created with corresponding public key, or a certificate was already available

        publicKeyFile = new File(workingDirectory, "public.pem");
        if (publicKeyFile.exists()) {
            if (password.length == 0) {
                throw new InitializationException("No password given as argument");
            }
            try {
                String pem = IOUtils.toString(new FileInputStream(publicKeyFile));
                byte[] pkcs12 = IOUtils.toByteArray(new FileInputStream(certFile));
                if (checkValidity(pem, pkcs12, password)) {
                    out("Validity check succeeded");
                    SeccocoImpl seccoco = new SeccocoImpl();
                    String fingerprint = DefaultIdentities.extractFingerPrint(securityProviderConnector.extractCertificate(new StringReader(pem)));
                    Identity ownIdentity = new Identity(pem,fingerprint);
                    File propertiesFile = new File(workingDirectory,"seccoco.props");
                    char[] appSecret;
                    String dat1  = "dat1";
                    if(propertiesFile.exists()) {
                        appSecret = readAppPassword(dat1,propertiesFile,pkcs12,password);
                    } else {
                        appSecret = storeAppPassword(dat1,propertiesFile,ownIdentity);
                    }
                    DefaultIdentities defaultIdentities = new DefaultIdentities(new File(argumentList.getWorkingDirectory(),"certs"),ownIdentity);
                    DefaultCrypto defaultCrypto = new DefaultCrypto(password, pkcs12, defaultIdentities, appSecret, ownIdentity);
                    DefaultIO defaultIO = new DefaultIO(defaultIdentities, defaultCrypto, appSecret);
                    seccoco.setDefaultIO(defaultIO);
                    seccoco.setIdentities(defaultIdentities);
                    seccoco.setCrypto(defaultCrypto);
                    return seccoco;

                } else {
                    throw new InitializationException("public and private key don't fit together");
                }
            } catch (IOException e) {
                throw new InitializationException("could not read certificate");
            } catch (CertificateEncodingException e) {
                throw new InitializationException("could not extract certificate - wrong encoding");
            } catch (CryptoException e) {
                throw new InitializationException("could not extract certificate");
            }
        } else {
            throw new InitializationException("no public key available");
        }

    }

    private boolean createSelfSignedCertificate(File workingDirectory, char[] password, File defaultTokenFile)  {
        out("Creating selfsigned certificate");
        Certificates certificates = new Certificates(securityProviderConnector);
        StringWriter pemWriter = new StringWriter();
        try {
            FileOutputStream outputStream = new FileOutputStream(defaultTokenFile);
            certificates.create(componentName, password, pemWriter, outputStream);
            outputStream.flush();
            outputStream.close();
            out("The private key of the server is located here; " + defaultTokenFile.getAbsolutePath());
            out("This is  the public key of the server:");
            String publicKey = pemWriter.toString();
            out(publicKey);
            File pem = new File(workingDirectory, "public.pem");
            FileWriter pemFileWriter = new FileWriter(pem);
            IOUtils.write(publicKey, pemFileWriter);
            pemFileWriter.flush();
            pemFileWriter.close();
            out("The publickey is located here: " + pem.getAbsolutePath());
        } catch (IOException e) {
            throw new InitializationException("could not create token: " + e.toString());
        }
        return true;
    }

    private boolean checkValidity(String pem, byte[] pkcs12, char[] password)  {
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(securityProviderConnector);
        String randomPw = RandomStringUtils.randomAlphanumeric(15);
        if (asymmetricCrypto.containsPrivateKey(password, new ByteArrayInputStream(pkcs12))) {
            byte[] encrypted = asymmetricCrypto.encrypt(randomPw.getBytes(), new StringReader(pem));
            byte[] plain = asymmetricCrypto.decrypt(encrypted, password, new ByteArrayInputStream(pkcs12));
            return randomPw.equals(new String(plain));
        } else {
            throw new InitializationException("Wrong password or corrupt P12");
        }

    }



    private char[] readAppPassword(String key, File passwordFile,byte[] pkcs12,char[] password) {
        Properties metaDataProps = new Properties();
        try {
            metaDataProps.load(new FileReader(passwordFile));
            String encBase64 = metaDataProps.getProperty(key);
            byte[] enc = Base64.decode(encBase64);
            AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(securityProviderConnector);
            byte[] decrypted =  asymmetricCrypto.decrypt(enc, password, new ByteArrayInputStream(pkcs12));
            return new String(Base64.encode(decrypted)).toCharArray();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private char[] storeAppPassword(String key, File passwordFile,Identity ownIdentity) {
        Properties metaDataProps = new Properties();
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(new BCConnector());

        byte[] password = new BCConnector().generateSecretKey().getEncoded();
        char[] appSecret = Base64.toBase64String(password).toCharArray();
        byte[] encryptedPassword = asymmetricCrypto.encrypt(password, new StringReader(ownIdentity.getCertificate()));
        byte[] base64 = Base64.encode(encryptedPassword);
        String encBase64 =  new String(base64);
        metaDataProps.put(key,encBase64);
        try {
            metaDataProps.store(new FileWriter(passwordFile), "Data");
            return appSecret;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }



    private void out(String msg) { outputWriter.println(msg);
    }

    public interface OutputWriter {
        void println(String message);
    }

}
