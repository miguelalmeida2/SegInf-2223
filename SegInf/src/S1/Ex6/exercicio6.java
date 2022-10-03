package S1.Ex6;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import java.nio.charset.Charset;
import java.security.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Scanner;


public class exercicio6 {

    public static void main(String[] args) {

        String fun = args[0];
        String fileIn = args[1];
        String cert = args[2];

        System.out.println(fun + " " + fileIn + " " + cert);

        


    }


    public static String readFile(String path, Charset encoding) {
        byte[] encoded = new byte[0];
        try {
            encoded = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(encoded, encoding);
    }


    /**
     * Generates the key for the AES algorithm
     *
     * @return SecretKey object to encrypt file with
     */
    private static SecretKey generateKey() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();

        String outFile = null;
        FileOutputStream out = new FileOutputStream(outFile + ".key");
        out.write(pvt.getEncoded());
        out.close();

        out = new FileOutputStream(outFile + ".pub");
        out.write(pvt.getEncoded());
        out.close();

        System.err.println("Private key format: " + pvt.getFormat());
        // prints "Private key format: PKCS#8" on my machine

        System.err.println("Public key format: " + pub.getFormat());
        // prints "Public key format: X.509" on my machine

        return (SecretKey) pvt;
    }
}

