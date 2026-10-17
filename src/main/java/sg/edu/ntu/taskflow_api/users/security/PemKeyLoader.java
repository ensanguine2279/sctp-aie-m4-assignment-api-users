package sg.edu.ntu.taskflow_api.users.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class PemKeyLoader {

    private static final Logger logger = LoggerFactory.getLogger(PemKeyLoader.class);

    public enum KeyType {
        PRIVATE("PRIVATE KEY"),
        PUBLIC("PUBLIC KEY");

        private final String label;

        KeyType(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    private PemKeyLoader() {
    }

    public static PrivateKey loadPrivateKey(String path) {
        // logger.info("Loading private key from path: {}", path);
        try {
            byte[] der = decodePem(Files.readString(Path.of(path)), KeyType.PRIVATE.getLabel());
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IOException | GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Could not load private key from " + path, ex);
        }
    }

    public static PublicKey loadPublicKey(String path) {
        try {
            byte[] der = decodePem(Files.readString(Path.of(path)), KeyType.PUBLIC.getLabel());
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (IOException | GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Could not load public key from " + path, ex);
        }
    }

    public static PublicKey derivePublicKey(PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey crt)) {
            throw new IllegalStateException("Private key must be an RSA CRT key to derive the public key");
        }
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Could not derive public key from private key", ex);
        }
    }

    private static byte[] decodePem(String pem, String type) {
        String body = pem
                .replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
}