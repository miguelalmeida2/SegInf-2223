package S1.Ex7;
/*
No exercício 7 não podem usar bibliotecas externas com exceção da biblioteca Apache Commons
 para codificar/descodificar em Base64. O restante código deve ser feito recorrendo à JCA.
 Devem organizar o código em classes separadas, e.g., RS256Signature, HS256Signature, JWT, etc
 */

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RS256Signature {
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.encodeBase64URLSafeString(signature);
    }

    public static void verify(){ //verificaçao

    }
}
