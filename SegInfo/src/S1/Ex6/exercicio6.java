package S1.Ex6;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;


public class exercicio6 {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        //String fun = args[0];
        //String fileIn = args[1];
        //String cert = args[2];

        //System.out.println(fun + " " + fileIn + " " + cert);


        // Assume que ficheiro cert.cer está na diretoria de execução.
        FileInputStream in = new FileInputStream("src/S1/Ex6/Alice_1.cer");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(
                new FileInputStream("src/S1/Ex6/Alice_1.pfx"),
                "changeit".toCharArray()
        );


        // Gera objeto para certificados X.509.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // Gera o certificado a partir do ficheiro.
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(in);
        // Obtém a chave pública do certificado.
        Enumeration<String> entries = ks.aliases();
        String alias = entries.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        PublicKey publicKeyKe = certificate.getPublicKey();
        PrivateKey privKeyKd = (PrivateKey) ks.getKey(alias, "changeit".toCharArray());

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        //KeyPairGenerator keyPairGenGa = KeyPairGenerator.getInstance("RSA");



        final String AES_CIPHER_ALGORITHM
                = "AES/CBC/PKCS5PADDING";

        /*
        keyPairGenGa.initialize(2048);
        KeyPair pair = keyPairGenGa.generateKeyPair();
        PrivateKey privKeyKd = pair.getPrivate();
        PublicKey publicKeyKe = pair.getPublic();

         */

        /**
         * -------------------------------- Encryption Side ------------------------------------------
         */


        Cipher cipherMen = Cipher.getInstance("AES");
        Cipher cipherKey = Cipher.getInstance("RSA");

        SecretKey keyK = keyGen.generateKey();

        // Associa a chave key a cifra
        cipherMen.init(Cipher.ENCRYPT_MODE, keyK);

        // Associa a chave publicKey a chaveK
        cipherKey.init(Cipher.WRAP_MODE,publicKeyKe);

        String fileName = "ficheiro.txt";
        File file = new File("src/S1/Ex6/"+fileName);
        FileInputStream fis = new FileInputStream("src/S1/Ex6/"+fileName);
        FileOutputStream outputStream = new FileOutputStream("src/S1/Ex6/encrypted_ficheiro.cif");
        //CipherInputStream cipherStream = new CipherInputStream(fis,cipherMen);
        Base64OutputStream encoder =  new Base64OutputStream(outputStream);


        /*
        System.out.println("Message Bytes:");
        prettyPrint(fis.readAllBytes());
        System.out.println("\n");

         */


        /*
        byte[] buffer = new byte[64];
        int nBytes;
        while ( (nBytes = cipherStream.read(buffer, 0, 64)) != -1 )
            encoder.write(buffer, 0, nBytes);

         */
        cmEnconding(encoder, cipherMen,fis,file);


        /**
         * -------------------------------- Decryption Side ------------------------------------------
         */

        byte[] bytesKey = ck(keyK, cipherKey);

        cipherKey.init(Cipher.UNWRAP_MODE,privKeyKd);

        //Chave secreta é estraida, é assegurado que é igual à chave gerada
        SecretKey secretKey = (SecretKey) cipherKey.unwrap(bytesKey,"AES",Cipher.SECRET_KEY);
        assert secretKey == keyK : "Extracted Key doesn't match Generated Key.  keyK != SecretKey";

        cipherMen.init(Cipher.DECRYPT_MODE,secretKey);


        FileInputStream cis = new FileInputStream("src/S1/Ex6/encrypted_ficheiro.cif");
        FileOutputStream outputStreamDecode = new FileOutputStream("src/S1/Ex6/decrypted_ficheiro.txt");
        Base64InputStream decoder = new Base64InputStream(cis);
        //CipherOutputStream cipherOutStream = new CipherOutputStream(outputStreamDecode, cipherMen);




        cmDecoding(decoder,cipherMen, outputStreamDecode);


    }

    /**
     * @param keyK
     * @param cipherKey
     * @return
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    private static byte[] ck(SecretKey keyK, Cipher cipherKey) throws IllegalBlockSizeException, InvalidKeyException {
        return cipherKey.wrap(keyK);
    }


    /**
     * @param encoder
     * @param cipher
     * @param cipherStream
     * @param file
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    private static void cmEnconding(Base64OutputStream encoder, Cipher cipher, FileInputStream cipherStream, File file) throws IllegalBlockSizeException, BadPaddingException, IOException {

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
     * @param decoder
     * @param cipher
     * @param cipherOutStream
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
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
            //cipherOutStream.write(outputBytes);
            cipherOutStream.write(outputBytes);
        }
        //prettyPrint(decoder.readAllBytes());



        decoder.close();
        cipherOutStream.close();
    }


    /**
     *
     * @param tag
     */
    private static void prettyPrint(byte[] tag) {
        for (byte b: tag) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }


    /**
     * /**
     * Generates the key for the AES algorithm
     *
     * @return SecretKey object to encrypt file with
     * @throws NoSuchAlgorithmException
     * @throws IOException
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

