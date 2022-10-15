package S1.Ex6;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class test {
    public static void main(String[] args) throws IOException {
        Base64 base64 = new Base64();

        FileInputStream fis = new FileInputStream("src/S1/Ex6/ficheiro.txt");
        byte [] bytes = fis.readAllBytes();

        FileOutputStream baseOut = new FileOutputStream("test_file.cif");
        Base64OutputStream out = new Base64OutputStream(baseOut);

        out.write(bytes);
        out.close();
        //baseOut.write(base64.encode(bytes));
        //baseOut.close();


        FileInputStream baseIn = new FileInputStream("test_file.cif");
        Base64InputStream in = new Base64InputStream(baseIn);

        int value;

        /*
        String encryptedString = new String(baseIn.readAllBytes());
        String decodedString = new String(base64.decode(encryptedString.getBytes()));

         */
        //String decodedString = new String(base64.decode(baseIn.readAllBytes()));
        FileOutputStream outputStreamDecode = new FileOutputStream("decrypted_test_file.txt");
        String decodedString = new String(in.readAllBytes());
        System.out.println(decodedString);

        outputStreamDecode.write(decodedString.getBytes());
        outputStreamDecode.close();



        while ((value = in.read()) != -1) {
            System.out.println(value);
        }
        in.close();
    }
}

