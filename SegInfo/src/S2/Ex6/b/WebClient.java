package S2.Ex6.b;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


public class WebClient {
    private static final String URL = "www.secure-server.edu";
    private static final int PORT = 4433;
    private static final String PFX = "Alice_2.pfx";
    private static final String PFX_PASSWORD = "changeit";
    private static final char[] PFX_PASSWORD_BYTE_ARRAY = PFX_PASSWORD.toCharArray();
    private static final String SERVER_CERTIFICATE = "S2/Ex6/a/secure-server.cer";
    private static final String SECURE_RANDOM_INSTANCE = "SHA1PRNG";
    private static final String CERTIFICATE_FACTORY_INSTANCE = "X.509";
    private static final String KEYSTORE_TYPE = KeyStore.getDefaultType();
    private static final String TRUST_MANAGER_FACTORY_ALGORITHM = TrustManagerFactory.getDefaultAlgorithm();
    private static final String KEY_MANAGER_FACTORY_ALGORITHM = KeyManagerFactory.getDefaultAlgorithm();
    private static final String SSL_ALGORITHM = "TLS";
    private static final String CERTIFICATE_ENTRY_NAME = "serverCertification";

    public static InputStream readResourceFile(String path) {
        return ClassLoader.getSystemResourceAsStream(path);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {

        final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_FACTORY_INSTANCE);

        try(final InputStream secureServerCertInputStream = readResourceFile(SERVER_CERTIFICATE)) {

            final Certificate secureServerCert = certificateFactory.generateCertificate(secureServerCertInputStream);
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

            keyStore.load(readResourceFile(PFX), PFX_PASSWORD_BYTE_ARRAY);
            keyStore.setCertificateEntry(CERTIFICATE_ENTRY_NAME, secureServerCert);

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TRUST_MANAGER_FACTORY_ALGORITHM);
            trustManagerFactory.init(keyStore);
            final TrustManager[] trustManagerArray = trustManagerFactory.getTrustManagers();

            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY_ALGORITHM);
            keyManagerFactory.init(keyStore, PFX_PASSWORD_BYTE_ARRAY);
            final KeyManager[] keyManagerArray = keyManagerFactory.getKeyManagers();

            final SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_INSTANCE);

            final SSLContext sslContext = SSLContext.getInstance(SSL_ALGORITHM);
            sslContext.init(keyManagerArray, trustManagerArray, secureRandom);

            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            final SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(URL, PORT);

            final SSLSession sslSession = sslSocket.getSession();

            final Certificate firstPeerCertificate = sslSession.getPeerCertificates()[0];

            System.out.println("Peer: " + firstPeerCertificate);

            final String cipherSuite = sslSession.getCipherSuite();

            System.out.println("Suite: " + cipherSuite);
        }
    }
}