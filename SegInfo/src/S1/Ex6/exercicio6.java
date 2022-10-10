package S1.Ex6;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
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
        KeyPairGenerator keyPairGenGa = KeyPairGenerator.getInstance("RSA");



        final String AES_CIPHER_ALGORITHM
                = "AES/CBC/PKCS5PADDING";

        /*
        keyPairGenGa.initialize(2048);
        KeyPair pair = keyPairGenGa.generateKeyPair();
        PrivateKey privKeyKd = pair.getPrivate();
        PublicKey publicKeyKe = pair.getPublic();

         */

        //Para MAC:        FileInputStream fis = new FileInputStream("src/S1/Ex6/ficheiro.txt");
        FileInputStream fis = new FileInputStream("src/S1/Ex6/ficheiro.txt");
        FileOutputStream outputStream = new FileOutputStream("src/S1/Ex6/output.txt");


        SecretKey keyK = keyGen.generateKey();

        //Chave Gerada
        //prettyPrint(keyK.getEncoded());

        System.out.println("Message Bytes:");
        prettyPrint(Base64.encodeBase64(fis.readAllBytes()));
        System.out.println("\n");

        Cipher cipherMen = Cipher.getInstance("AES");
        Cipher cipherKey = Cipher.getInstance("RSA");


        CipherInputStream cis = new CipherInputStream(fis,cipherMen);

        // Associa a chave key a cifra
        cipherMen.init(Cipher.ENCRYPT_MODE, keyK);

        // Associa a chave publicKey a chaveK
        cipherKey.init(Cipher.WRAP_MODE,publicKeyKe);

        cm(fis, cipherMen, outputStream);




        byte[] bytesKey = ck(keyK, cipherKey);

        // Mostra os bytes em hexadec
        //prettyPrint(bytes);
        //prettyPrint(bytesKey);

        cipherKey.init(Cipher.UNWRAP_MODE,privKeyKd);

        //Chave secreta é estraida, é assegurado que é igual à chave gerada
        SecretKey secretKey = (SecretKey) cipherKey.unwrap(bytesKey,"AES",Cipher.SECRET_KEY);
        assert secretKey == keyK : "Extracted Key doesn't match Generated Key.  keyK != SecretKey";

        cipherMen.init(Cipher.DECRYPT_MODE,secretKey);

        //byte[] msg = Base64.decodeBase64(cipherMen.doFinal(bytes));

        FileInputStream fos = new FileInputStream("src/S1/Ex6/output.txt");
        FileOutputStream decodedMessage = new FileOutputStream("src/S1/Ex6/decodedMessage.txt");

        cm(fos,cipherMen,decodedMessage);

        System.out.println("Message Bytes After Decoding");
        //prettyPrint(decodedMessage);
    }

    private static byte[] ck(SecretKey keyK, Cipher cipherKey) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] bytesKey = cipherKey.wrap(keyK);
        return bytesKey;
    }
    //Meter nome do ficheiro em vez de input e output stream
    private static void cm(FileInputStream fis, Cipher cipher, FileOutputStream fos) throws IllegalBlockSizeException, BadPaddingException, IOException {
        // Cifra mensagem com chave key
        //byte [] readBytes = Base64.encodeBase64(fis.readAllBytes())


        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                fos.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            fos.write(outputBytes);
        }
        fis.close();
        fos.close();
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

