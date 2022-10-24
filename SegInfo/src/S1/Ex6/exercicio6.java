package S1.Ex6;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Scanner;


public class exercicio6 {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        if(args.length==0) {
            Scanner sc= new Scanner(System.in);
            System.out.println(" Welcome to the SegInf Cypher & Decipher Program.\n");
            System.out.println("    Please select the desired mode: ");
            System.out.println("     -enc  [Encodes a file, ciphering it's content]");
            System.out.println("     -dec  [Decodes a file, deciphering it's content]");

            String userResponse = sc.nextLine();
            switch (userResponse) {
                case "-enc" -> {
                    String [] newArgs = new String[3];
                    System.out.println("> Please Introduce A File To Cipher :");
                    newArgs[1] = sc.nextLine();
                    System.out.println("> Please Introduce A Certificate :");
                    newArgs[2] = sc.nextLine();
                    encMode(newArgs);
                }
                case "-dec" -> {
                    String [] newArgs = new String[4];
                    System.out.println("> Please Introduce A Ciphered Message File :");
                    newArgs[1] = sc.nextLine();
                    System.out.println("> Please Introduce A Ciphered Secret Key :");
                    newArgs[2] = sc.nextLine();
                    System.out.println("> Please Introduce A KeyStore Private Key :");
                    newArgs[3] = sc.nextLine();
                    decMode(newArgs);
                }
                default -> throw new IllegalArgumentException("Incorrect Mode, please introduce either -enc or -dec .");
            }
        }else {
            String mode = args[0];
            switch (mode) {
                case "-enc" -> encMode(args);
                case "-dec" -> decMode(args);
                default -> throw new IllegalArgumentException("Incorrect Mode, please introduce either -enc or -dec .");
            }
        }

    }

    /**
    * ----------------------------------------------------------- Encoding Side --------------------------------------------------------------------
    */

    /**
     * Encode Mode, receives the Original message and the public key certificate (.cer file) from the sender.
     * Generates a Secret Key.
     * Uses the Secret Key to Encrypt the original message into a ciphered File called "encrypted_ficheiro.txt"
     * Retrieves the Public Key from the .cer file received, and uses it to wrap the Secret Key into a file named "encrypted_symmetric_key.txt".
     *
     * @param args
     */
    private static void encMode(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, CertificateException {
        // -enc [ficheiro para cifrar] [ficheiro com chave publica]
        // -enc ficheiro.txt src/S1/Ex6/Alice_1.cer

        String fileName = args[1]; //file to encode
        String cert = args[2]; //"src/S1/Ex6/Alice_1.cer"
        FileInputStream in = new FileInputStream(cert); //certificado



        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        Cipher cipherMen = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher cipherKey = Cipher.getInstance("RSA");

        // Gera objeto para certificados X.509.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // Gera o certificado a partir do ficheiro.
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(in);


        PublicKey publicKeyKe = certificate.getPublicKey();

        SecretKey keyK = keyGen.generateKey();

        // Associa a chave key a cifra
        cipherMen.init(Cipher.ENCRYPT_MODE, keyK);

        // Associa a chave publicKey a chaveK
        cipherKey.init(Cipher.WRAP_MODE,publicKeyKe);

        //File file = new File("src/S1/Ex6/"+fileName);
        FileInputStream fis = new FileInputStream("src/S1/Ex6/"+fileName);
        FileOutputStream outputStream = new FileOutputStream("src/S1/Ex6/encrypted_ficheiro.txt");
        //CipherInputStream cipherStream = new CipherInputStream(fis,cipherMen);
        Base64OutputStream encoder =  new Base64OutputStream(outputStream);

        cmEnconding(encoder,cipherMen,fis);
        ck(keyK, cipherKey);
    }

    /** Encodes and Ciphers the original message from the Sender to a ciphered File named "encrypted_[fileName].txt"
     * @param encoder
     * @param cipher
     * @param cipherStream
     */
    private static void cmEnconding(Base64OutputStream encoder, Cipher cipher, FileInputStream cipherStream) throws IllegalBlockSizeException, BadPaddingException, IOException {

        byte[] buffer = new byte[64];
        int bytesRead;


        while ((bytesRead = cipherStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                encoder.write(output);
            }
        }

        byte[] outputBytes = cipher.doFinal();

        if (outputBytes != null) {
            encoder.write(outputBytes);
        }


        encoder.close();
        cipherStream.close();
    }

    /**
     * Wraps the Secret Key into an encrypted file named "encrypted_symmetric_key.txt"
     * @param keyK
     * @param cipherKey
     * @return bytes, the wraped Secret Key Byte Array
     */
    private static byte[] ck(SecretKey keyK, Cipher cipherKey) throws IllegalBlockSizeException, InvalidKeyException, IOException {
        byte [] bytes = cipherKey.wrap(keyK);
        FileOutputStream outputStream = new FileOutputStream("src/S1/Ex6/encrypted_symmetric_key.txt");
        //Base64OutputStream toFile = new Base64OutputStream(outputStream);
        outputStream.write(bytes);
        System.out.println();
        System.out.println("Encrypted Key1:");
        prettyPrint(bytes);
        return bytes;
    }

    /**
     * ----------------------------------------------------------- Decoding Side --------------------------------------------------------------------
     */

    /**
     * Decode Mode, receives from args the Ciphered File, the Ciphered Symmetric Key File, and the Keystore Private Key from the Receiver.
     * Retrieves the Private Key from the .pfx file received in args[3] and uses it to unwrap the Secret Key used in the Symmetric Message Cipher (K from Cm = E(K)(m)
     * Once unwraped, the Secret Key is used to Decrypt the Ciphered File (Cm), the result is a generated "decrypted_[inputFileName].txt" with the original message
     * from the Sender.
     * @param args
     */
    private static void decMode(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // -dec [ficheiro cifrado] [ficheiro com chave simétrica cifrada] [keystore com a chave privada do dest.]
        // -dec src/S1/Ex6/encrypted_ficheiro.txt src/S1/Ex6/encrypted_symmetric_key.txt src/S1/Ex6/Alice_1.pfx

        Cipher cipherMen = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher cipherKey = Cipher.getInstance("RSA");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream privKey = new FileInputStream(args[3]);
        ks.load(
                privKey,
                "changeit".toCharArray()
        );

        Enumeration<String> entries = ks.aliases();
        String alias = entries.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        PrivateKey privKeyKd = (PrivateKey) ks.getKey(alias, "changeit".toCharArray());

        FileInputStream symmetricKey = new FileInputStream(args[2]); //src/S1/Ex6/encrypted_symmetric_key.txt
        //Base64InputStream symmetricKey64 = new Base64InputStream(symmetricKey);

        byte [] encryptedKey = symmetricKey.readAllBytes();
        System.out.println("Encrypted Key2:");
        prettyPrint(encryptedKey);

        cipherKey.init(Cipher.UNWRAP_MODE,privKeyKd);

        SecretKey secretKey = (SecretKey) cipherKey.unwrap(encryptedKey,"AES",Cipher.SECRET_KEY);

        cipherMen.init(Cipher.DECRYPT_MODE,secretKey);


        FileInputStream cis = new FileInputStream(args[1]); //"src/S1/Ex6/encrypted_ficheiro.txt"
        FileOutputStream outputStreamDecode = new FileOutputStream("src/S1/Ex6/decrypted_ficheiro.txt");
        Base64InputStream decoder = new Base64InputStream(cis);

        cmDecoding(decoder,cipherMen, outputStreamDecode);
    }

    /**
     * Decodes and decrypts from the encrypted file into a decrypted file. (m' = D(K)(Cm))
     * @param decoder
     * @param cipher
     * @param cipherOutStream
     */
    private static void cmDecoding(Base64InputStream decoder, Cipher cipher, FileOutputStream cipherOutStream) throws IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] buffer = new byte[64];
        int bytesRead;

        while ((bytesRead = decoder.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);

            if (output != null) {
                cipherOutStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        //cipherOutStream.write(new String(outputBytes).getBytes());


        if (outputBytes != null) {
            cipherOutStream.write(outputBytes);
        }

        decoder.close();
        cipherOutStream.flush();
        cipherOutStream.close();
    }


    /**
     *
     * @param tag, Byte Array to be printed
     */
    private static void prettyPrint(byte[] tag) {
        for (byte b: tag) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

}

