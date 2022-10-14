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
        File file = new File(filename);

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
        // Another way to encode to base64 without a Base64Stream -> byte[] encoded = Base64.encodeBase64(fis.readAllBytes());

        /**
         * Decoding from the file and writing to an output file
         */
        FileInputStream baseIn = new FileInputStream("Base64TestFile.cif");
        Base64InputStream in = new Base64InputStream(baseIn);

        FileOutputStream output = new FileOutputStream("output.txt");
        Base64OutputStream outputStream = new Base64OutputStream(output);

        int readBytes;
        byte[] buffer = new byte[64];
        while((readBytes = in.read(buffer,0,64)) != -1){
            outputStream.write(readBytes);
        }
        /*
        String result = new String(baseIn.readAllBytes(), StandardCharsets.UTF_8);
        System.out.println(result);

        System.out.println(Arrays.toString(Base64.decodeBase64(in.readAllBytes())));

         */

    }
}
