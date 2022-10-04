package S1.Ex5;

/*
Usando a biblioteca JCA, realize em Java uma aplicação para geração de hashs cripográficos de ficheiros.
A aplicação recebe na linha de comandos:
i) o nome da função de hash (SHA-1, SHA-256, MD5)
ii) o ficheiro para o qual se quer obter o hash.
O valor de hash é enviado para o standard output.
 */

import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Arrays;

public class exercicio5 {
    public static void main(String[] args) {
        try {
            System.out.println(Arrays.toString(args));
            String path = "C:\\Users\\david\\Documents\\GitHub\\SegInf-2223\\SegInfo\\src\\S1\\Ex5\\" + args[1];

            MessageDigest md = MessageDigest.getInstance(args[0]);
            FileInputStream fis = new FileInputStream(path);

            byte[] bytes = new byte[1024];
            int numBytes;
            while ((numBytes = fis.read(bytes)) != -1) {
                md.update(bytes, 0, numBytes);
            }
            byte[] digest = md.digest();

            //convert the byte to hex format
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }

            System.out.println("hash: " + sb);
        }
        catch (Exception e) {
            System.out.println("Exception thrown : " + e);
        }
    }
}
