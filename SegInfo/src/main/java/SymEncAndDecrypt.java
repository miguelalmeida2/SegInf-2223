import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Scanner;

public class SymEncAndDecrypt {
    private static String keyPassword = null;

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException {
        String res;
        Cipher cipher = null;
        do {
            System.out.println("Name of the file?(including .format");
            Scanner in = new Scanner(System.in);
            String fileName = in.nextLine();
            if(keyPassword==null){
                keyPassword = fileName;
            }

            Path path = Paths.get(fileName);
            byte[] fileContent = null;
            try {
                fileContent = Files.readAllBytes(path);
            } catch (IOException e) {
            }

            //entryPassword = new KeyStore.PasswordProtection(fileName.toCharArray());
            System.out.println("Encrypt or decrypt?");
            res = in.nextLine();


            //antes Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // The algorithm described by AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting the data, that's symmetric encryption
            if (cipher == null) {
                cipher = Cipher.getInstance("AES");
            }

            if (res.equalsIgnoreCase("encrypt")) {
                createAndStoreKey(generateKey());
                writeFile(encrypt(cipher, fileContent), "encrypted");
            } else if (res.equalsIgnoreCase("decrypt")) {
                writeFile(decrypt(cipher, fileContent), "decrypted");
            } else {
                System.out.println("Weird answer");
            }
        } while(!res.equalsIgnoreCase("finish"));
    }

    /**
     * Generates the key for the AES algorithm
     * @return SecretKey object to encrypt file with
     */
    private static SecretKey generateKey() {
        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (Exception e) { e.printStackTrace(); }
        SecretKey key = generator.generateKey();
        return key;
    }

    /**
     * Creates a keyStore and stores a key
     * @param key to be stored in the keyStore
     */
    private static void createAndStoreKey(SecretKey key) { //(a aplicação gera a chave e guarda-a em ficheiro próprio)
        try {//INSTACIAR keyStore
            KeyStore keyStore = KeyStore.getInstance("JCEKS"); //=JKS, alternaticamente, usa-se "PKCS12". The JKS keystore type only supports asymmetric (public/private) keys! https://stackoverflow.com/questions/18243248/java-keystore-setentry-using-an-aes-secretkey !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            //SET KEY
            char[] keyStorePassword = keyPassword.toCharArray();
            FileOutputStream keyStoreOutputStream = new FileOutputStream("keystore.ks"); //criar ficheiro

            keyStore.load(null, keyStorePassword);
            keyStore.store(keyStoreOutputStream, keyStorePassword);
            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyStorePassword); //password to the key
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key); //ACTUAL key
            //keyStore.store(keyStoreOutputStream, keyStorePassword); //para ver o keystore sem nada configurado
            keyStore.setEntry("keyAlias", secretKeyEntry, entryPassword);
            FileOutputStream keyStoreOutputStream2 = new FileOutputStream("keystore.ks");
            keyStore.store(keyStoreOutputStream2, keyStorePassword);
            //e CRIAR o ficheiro para tal

        } catch (Exception e) { e.printStackTrace(); }
    }

    /**
     * Before a keyStore is used it has to be loaded
     * @return a loaded keyStore
     */
    private static KeyStore loadKeyStore() {
        char[] keyStorePassword = keyPassword.toCharArray();
        KeyStore keyStore = null;
        try(InputStream keyStoreData = new FileInputStream("keystore.ks")){
            keyStore =  KeyStore.getInstance("JCEKS");
            keyStore.load(null, keyStorePassword); //só para ver como fica
            keyStore.load(keyStoreData, keyStorePassword);

        } catch (Exception e) { e.printStackTrace(); }
        return keyStore;
    }

    /**
     * @return return a cipher key
     */
    public static Key getKey(){
        char[] keyStorePassword = keyPassword.toCharArray();
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyStorePassword);
        KeyStore keyStore = loadKeyStore();
        Key key = null;
        try {
            //key = keyStore.getKey("keyAlias", keyStorePassword);
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("keyAlias", entryPassword);
            key = secretKeyEntry.getSecretKey();
        } catch (Exception e) { e.printStackTrace(); }
        return key;
    }

    /**
     * Encrypts a file
     * @param cipher cipher object to encrypt the file with
     * @param fileContent byte array with the file content
     * @return byte array with encrypted file
     */
    private static byte[] encrypt(Cipher cipher, byte[] fileContent) {
        byte[] ciphertext = null;
        try {
            Key key = getKey();
            cipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = cipher.doFinal(fileContent);
        } catch (Exception e) { e.printStackTrace(); }

        return ciphertext;
    }

    /**
     * Decrypts a file
     * @param cipher cipher object to decipher the file with
     * @param fileContent byte array with the file content
     * @return byte array with plaintext
     */
    private static byte[] decrypt(Cipher cipher, byte[] fileContent) {
        byte[] new_plaintext = null;
        try {
            Key key = getKey();
            //KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry();
            cipher.init(Cipher.DECRYPT_MODE, key); //é preciso new IvParameterSpec(cipher.getIV()) ?
            new_plaintext = cipher.doFinal(fileContent);
        } catch (Exception e) { e.printStackTrace(); }
        return new_plaintext;
    }

    /**
     * Writes text to a file
     * @param bytes bytes to be written to the file
     * @param path filepath
     */
    private static void writeFile(byte[] bytes, String path) {
        try {
            String filepath = keyPassword.substring(0, keyPassword.length()-4)+path+".txt";
            FileOutputStream outputStream = new FileOutputStream(filepath);
            outputStream.write(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
