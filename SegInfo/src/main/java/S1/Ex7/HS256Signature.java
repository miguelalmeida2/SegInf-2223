
package S1.Ex7;

/*
 No exercício 7 não podem usar bibliotecas externas com exceção da biblioteca Apache Commons
 para codificar/descodificar em Base64. O restante código deve ser feito recorrendo à JCA.
 Devem organizar o código em classes separadas, e.g., RS256Signature, HS256Signature, JWT, etc
 */
/*
import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

//import org.json.JSONObject;

public class HS256Signature {
    public static String SECRET = JWT.pdxPassword;
    public static String JWT_ALGO = "HS256";
    public static String ALGO = "HmacSHA256";

    public static String sign(String token) throws NoSuchAlgorithmException {
        String[] split = token.split("\\.");
        Mac mac = Mac.getInstance("HmacSHA256");

        byte[] signature = mac.doFinal((split[0] + "." + split[1]).getBytes());
        StringBuilder builder = new StringBuilder();
        builder.append(token)
                .append(signature);
        return Base64.encodeBase64URLSafeString(signature);
    }

    public static boolean verify(String jwt, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        String[] sections = jwt.split("\\.");
        String header = sections[0];
        String payld = sections[1];
        String sign = sections[2];

        byte[] expected = mac.doFinal((header + "." + payld).getBytes());
        String encodedExpected = Base64.encodeBase64URLSafeString(expected);
        return sign.equals(encodedExpected);
    }


    public static String generateToken(String user_data) {
        //JSONObject header = new JSONObject().append("alg", JWT_ALGO).append("typ", "JWT");
        String header_string = Base64.encodeBase64URLSafeString(header.toString().getBytes());

        String payload_string = Base64.encodeBase64URLSafeString(user_data.getBytes());

        String signed_string = header_string + "." + payload_string;

        String signature_string = getSignature(signed_string);

        return header_string + "." + payload_string + "." + signature_string;
    }

    public static String getSignature(String s) {
        String signature = "";
        try {
            SecretKeySpec signing = new SecretKeySpec(SECRET.getBytes(), ALGO);
            Mac mac = Mac.getInstance(ALGO);
            mac.init(signing);
            signature = Base64.encodeBase64URLSafeString(mac.doFinal(s.getBytes()));
        } catch (Exception e) {
            System.err.println("Problem: " + e.getMessage());
        }
        return signature;
    }
}
*/
