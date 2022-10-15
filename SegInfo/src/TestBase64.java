import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import java.io.*;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TestBase64 {

    public static void main(String[] args) throws IOException {
        String filename = "ficheiro.txt";

        /**
         * Source
         */
        FileInputStream fis = new FileInputStream("src/S1/Ex6/"+filename);

        /**
         * Destiny
         */
        FileOutputStream fos = new FileOutputStream("Base64TestFile.cif");
        Base64OutputStream base64OutputStream = new Base64OutputStream(fos);


        /**
         * Encoding in Base64 to a file
         */
        base64OutputStream.write(fis.readAllBytes());

        base64OutputStream.close();


        // Another way to encode to base64 without a Base64Stream -> byte[] encoded = Base64.encodeBase64(fis.readAllBytes());

        /**
         * Decoding from the file and writing to an output file
         */
        FileInputStream baseIn = new FileInputStream("Base64TestFile.cif");
        Base64InputStream in = new Base64InputStream(baseIn);

        FileOutputStream output = new FileOutputStream("output.txt");
        Base64OutputStream outputStream = new Base64OutputStream(output);

        byte [] input = in.readAllBytes();
        outputStream.write(Base64.decodeBase64(input));

        /*
        System.out.println(Arrays.toString(Base64.decodeBase64(in.readAllBytes())));

         */

    }
}
