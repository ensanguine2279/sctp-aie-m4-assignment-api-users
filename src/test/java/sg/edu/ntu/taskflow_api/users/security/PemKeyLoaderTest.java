package sg.edu.ntu.taskflow_api.users.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemKeyLoaderTest {

    private static KeyPair rsaPair;

    @TempDir
    Path tmp;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        rsaPair = gen.generateKeyPair();
    }

    // ---------- helpers ----------

    private Path writePem(String name, String label, byte[] der, String lineSeparator) throws IOException {
        String body = Base64.getMimeEncoder(64, lineSeparator.getBytes(StandardCharsets.UTF_8))
                .encodeToString(der);
        return Files.writeString(tmp.resolve(name),
                "-----BEGIN " + label + "-----" + lineSeparator
                        + body + lineSeparator
                        + "-----END " + label + "-----" + lineSeparator);
    }

    private Path writePrivatePem() throws IOException {
        return writePem("private.pem", "PRIVATE KEY", rsaPair.getPrivate().getEncoded(), "\n");
    }

    private Path writePublicPem() throws IOException {
        return writePem("public.pem", "PUBLIC KEY", rsaPair.getPublic().getEncoded(), "\n");
    }

    // ---------- loadPrivateKey(path) ----------

    @Test
    void loadPrivateKey_validPkcs8_returnsMatchingKey() throws IOException {
        Path file = writePrivatePem();

        PrivateKey loaded = PemKeyLoader.loadPrivateKey(file.toString());

        assertArrayEquals(rsaPair.getPrivate().getEncoded(), loaded.getEncoded());
    }

    @Test
    void loadPrivateKey_toleratesWindowsLineEndings() throws IOException {
        Path file = writePem("crlf.pem", "PRIVATE KEY", rsaPair.getPrivate().getEncoded(), "\r\n");

        PrivateKey loaded = PemKeyLoader.loadPrivateKey(file.toString());

        assertArrayEquals(rsaPair.getPrivate().getEncoded(), loaded.getEncoded());
    }

    @Test
    void loadPrivateKey_toleratesKeyOnOneLineWithoutTrailingNewline() throws IOException {
        String body = Base64.getEncoder().encodeToString(rsaPair.getPrivate().getEncoded());
        Path file = Files.writeString(tmp.resolve("oneline.pem"),
                "-----BEGIN PRIVATE KEY-----" + body + "-----END PRIVATE KEY-----");

        PrivateKey loaded = PemKeyLoader.loadPrivateKey(file.toString());

        assertArrayEquals(rsaPair.getPrivate().getEncoded(), loaded.getEncoded());
    }

    @Test
    void loadPrivateKey_missingFile_throwsAndNamesThePath() {
        String missing = tmp.resolve("nope.pem").toString();

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> PemKeyLoader.loadPrivateKey(missing));

        assertTrue(ex.getMessage().contains(missing));
    }

    @Test
    void loadPrivateKey_emptyFile_throws() throws IOException {
        Path file = Files.writeString(tmp.resolve("empty.pem"), "");

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPrivateKey(file.toString()));
    }

    @Test
    void loadPrivateKey_garbageContent_throws() throws IOException {
        Path file = Files.writeString(tmp.resolve("garbage.pem"), "this is not a pem file");

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPrivateKey(file.toString()));
    }

    @Test
    void loadPrivateKey_validBase64ButNotAKey_throws() throws IOException {
        Path file = writePem("notakey.pem", "PRIVATE KEY", "just some bytes".getBytes(StandardCharsets.UTF_8), "\n");

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPrivateKey(file.toString()));
    }

    @Test
    void loadPrivateKey_rsaPrivateKeyHeader_isNotSupported() throws IOException {
        // "BEGIN RSA PRIVATE KEY" is PKCS#1; the loader only accepts PKCS#8 ("BEGIN PRIVATE KEY")
        Path file = writePem("pkcs1.pem", "RSA PRIVATE KEY", rsaPair.getPrivate().getEncoded(), "\n");

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPrivateKey(file.toString()));
    }

    @Test
    void loadPrivateKey_givenPublicKeyFile_throws() throws IOException {
        Path file = writePublicPem();

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPrivateKey(file.toString()));
    }

    // ---------- loadPublicKey(path) ----------

    @Test
    void loadPublicKey_validX509_returnsMatchingKey() throws IOException {
        Path file = writePublicPem();

        PublicKey loaded = PemKeyLoader.loadPublicKey(file.toString());

        assertArrayEquals(rsaPair.getPublic().getEncoded(), loaded.getEncoded());
    }

    @Test
    void loadPublicKey_missingFile_throwsAndNamesThePath() {
        String missing = tmp.resolve("nope.pem").toString();

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> PemKeyLoader.loadPublicKey(missing));

        assertTrue(ex.getMessage().contains(missing));
    }

    @Test
    void loadPublicKey_garbageContent_throws() throws IOException {
        Path file = Files.writeString(tmp.resolve("garbage-public.pem"), "this is not a pem file");

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPublicKey(file.toString()));
    }

    @Test
    void loadPublicKey_givenPrivateKeyFile_throws() throws IOException {
        Path file = writePrivatePem();

        assertThrows(IllegalStateException.class, () -> PemKeyLoader.loadPublicKey(file.toString()));
    }
}