package sg.edu.ntu.taskflow_api.users;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.util.Base64;

import org.springframework.test.context.DynamicPropertyRegistry;

final class TestJwtKeys {

    static final String ISSUER = "users-service";
    static final String AUDIENCE = "tasks-api";

    static final KeyPair SIGNING_KEYS = newKeyPair();
    static final KeyPair OTHER_KEYS = newKeyPair();
    static final Path SIGNING_KEY_FILE = writePrivatePem(SIGNING_KEYS);
    static final Path OTHER_KEY_FILE = writePrivatePem(OTHER_KEYS);

    private TestJwtKeys() {
    }

    static void register(DynamicPropertyRegistry registry) {
        registry.add("jwt.private-key-path", () -> SIGNING_KEY_FILE.toString());
        // The base64 key wins over the path. Without this line, a
        // JWT_PRIVATE_KEY_BASE64 exported in the developer's shell (for example while
        // trying out a Railway deployment) would silently replace the test key.
        registry.add("jwt.private-key-base64", () -> "");
        registry.add("jwt.issuer", () -> ISSUER);
        registry.add("jwt.audience", () -> AUDIENCE);
        registry.add("jwt.expiration-ms", () -> "3600000");
    }

    private static KeyPair newKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not generate test RSA key pair", ex);
        }
    }

    private static Path writePrivatePem(KeyPair pair) {
        try {
            String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                    .encodeToString(pair.getPrivate().getEncoded());
            Path file = Files.createTempFile("test-private-", ".pem");
            file.toFile().deleteOnExit();
            return Files.writeString(file,
                    "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n");
        } catch (IOException ex) {
            throw new IllegalStateException("Could not write test private key", ex);
        }
    }
}