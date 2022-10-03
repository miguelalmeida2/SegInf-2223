package S1.Ex6;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Scanner;


public class exercicio6 {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        String fun = args[0];
        String fileIn = args[1];
        String cert = args[2];

        System.out.println(fun + " " + fileIn + " " + cert);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        KeyPairGenerator keyPairGenGa = KeyPairGenerator.getInstance("RSA");

        keyPairGenGa.initialize(2048);
        KeyPair pair = keyPairGenGa.generateKeyPair();
        PrivateKey privKeyKd = pair.getPrivate();
        PublicKey publicKeyKe = pair.getPublic();

        FileInputStream fis = new FileInputStream("src/S1/Ex6/ficheiro.txt");

        SecretKey keyK = keyGen.generateKey();

        Cipher cipherMen = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher cipherKey = Cipher.getInstance("RSA");


        CipherInputStream cis = new CipherInputStream(fis,cipherMen);

        // Associa a chave key a cifra
        cipherMen.init(Cipher.ENCRYPT_MODE, keyK);

        // Associa a chave publicKey a chaveK
        cipherKey.init(Cipher.WRAP_MODE,publicKeyKe);

        byte[] bytes = cm(fis, cipherMen);

        byte[] bytesKey = ck(keyK, cipherKey);

        // Mostra os bytes em hexadec
        prettyPrint(bytes);
        prettyPrint(bytesKey);

        cipherKey.init(Cipher.UNWRAP_MODE,privKeyKd);
        SecretKey secretKey = (SecretKey) cipherKey.unwrap(bytesKey,"RSA",Cipher.SECRET_KEY);


        cipherMen.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] msg = Base64.decodeBase64(cipherMen.doFinal(bytes));
        System.out.println(msg);
    }

    private static byte[] ck(SecretKey keyK, Cipher cipherKey) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] bytesKey = cipherKey.wrap(keyK);
        return bytesKey;
    }

    private static byte[] cm(FileInputStream fis, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException, IOException {
        // Cifra mensagem com chave key
        byte[] bytes = cipher.doFinal(fis.readAllBytes());
        return bytes;
    }

    // Imprime array de bytes em hexadecimal
    private static void prettyPrint(byte[] tag) {
        for (byte b: tag) {
            System.out.printf("%02x", b);
        }
        System.out.println();
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

