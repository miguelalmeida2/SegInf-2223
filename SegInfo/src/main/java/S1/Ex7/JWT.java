package S1.Ex7;
import org.apache.commons.codec.binary.*;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;


public class JWT {

    public static final String pdxPassword = "changeit";
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        System.out.println("Enter json file name: \n");
        Scanner in = new Scanner(System.in);
        String fileName = in.nextLine();
        Path path = Paths.get(fileName);
        String content = readFile(path.toString(), StandardCharsets.US_ASCII );

        System.out.println("Sign with HS256 or RS256?");
        String res = in.nextLine();

        if(res.equalsIgnoreCase("HS256")){
            //HS256Signature.sign(content);
        } else {
            SecretKey secretKey = generateKey();
            //RS256Signature.sign(content, );
        }
    }

    public static String readFile(String path, Charset encoding) {
        byte[] encoded = new byte[0];
        try {
            encoded = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) { e.printStackTrace(); }
        return new String(encoded, encoding);
    }

    /**
     * Generates the key for the AES algorithm
     * @return SecretKey object to encrypt file with
     */
    private static SecretKey generateKey() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();

        String outFile = null;
        FileOutputStream out = new FileOutputStream(".key");
        out.write(pvt.getEncoded());
        out.close();

        out = new FileOutputStream(".pub");
        out.write(pvt.getEncoded());
        out.close();

        System.err.println("Private key format: " + pvt.getFormat());
        // prints "Private key format: PKCS#8" on my machine

        System.err.println("Public key format: " + pub.getFormat());
        // prints "Public key format: X.509" on my machine
        return null;
    }
}
