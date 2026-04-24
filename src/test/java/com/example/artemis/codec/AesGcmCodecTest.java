package com.example.artemis.codec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmCodecTest {

    private String base64Key;
    private AesGcmCodec codec;

    @BeforeEach
    void setUp() throws Exception {
        base64Key = AesGcmCodec.generateBase64Key();
        codec = new AesGcmCodec();
        Map<String, String> params = new HashMap<>();
        params.put("key", base64Key);
        codec.init(params);
    }

    // ------------------------------------------------------------------
    // Encode / decode round-trip
    // ------------------------------------------------------------------

    @Test
    void encodeThenDecodeReturnsOriginal() throws Exception {
        String plaintext = "MyS3cretP@ssword!";
        String masked = codec.encode(plaintext);
        String decoded = codec.decode(masked);
        assertEquals(plaintext, decoded);
    }

    @Test
    void twoEncodesOfSamePasswordProduceDifferentMasks() throws Exception {
        // GCM uses a random IV per invocation — same input must not produce the same output
        String masked1 = codec.encode("same-password");
        String masked2 = codec.encode("same-password");
        assertNotEquals(masked1, masked2, "Random IV must make each encoding unique");
    }

    @Test
    void emptyPasswordRoundTrips() throws Exception {
        String masked  = codec.encode("");
        String decoded = codec.decode(masked);
        assertEquals("", decoded);
    }

    @Test
    void unicodePasswordRoundTrips() throws Exception {
        String password = "Pässwörд-日本語-🔐";
        assertEquals(password, codec.decode(codec.encode(password)));
    }

    // ------------------------------------------------------------------
    // Tampering detection (GCM authentication tag)
    // ------------------------------------------------------------------

    @Test
    void tamperingCiphertextThrowsException() throws Exception {
        String masked = codec.encode("secret");
        // Flip a byte near the end of the Base64 payload
        char[] chars = masked.toCharArray();
        chars[chars.length - 2] = chars[chars.length - 2] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);
        assertThrows(Exception.class, () -> codec.decode(tampered),
            "GCM should reject tampered ciphertext");
    }

    // ------------------------------------------------------------------
    // verify()
    // ------------------------------------------------------------------

    @Test
    void verifyReturnsTrueForMatchingPassword() throws Exception {
        String password = "correct-horse-battery-staple";
        String masked   = codec.encode(password);
        assertTrue(codec.verify(password.toCharArray(), masked));
    }

    @Test
    void verifyReturnsFalseForWrongPassword() throws Exception {
        String masked = codec.encode("correct-password");
        assertFalse(codec.verify("wrong-password".toCharArray(), masked));
    }

    // ------------------------------------------------------------------
    // Key resolution
    // ------------------------------------------------------------------

    @Test
    void keyFromFileResolvesCorrectly(@TempDir Path tempDir) throws Exception {
        Path keyFile = tempDir.resolve("codec.key");
        Files.writeString(keyFile, base64Key);

        AesGcmCodec fileCodec = new AesGcmCodec();
        Map<String, String> params = new HashMap<>();
        params.put("key-location", keyFile.toString());
        fileCodec.init(params);

        String masked  = fileCodec.encode("hello");
        String decoded = fileCodec.decode(masked);
        assertEquals("hello", decoded);
    }

    @Test
    void wrongKeySizeThrowsIllegalArgument() {
        AesGcmCodec badCodec = new AesGcmCodec();
        Map<String, String> params = new HashMap<>();
        // 16 bytes = AES-128, not AES-256 — should be rejected
        params.put("key", "dGhpcyBpcyAxNiBieXRlcw=="); // "this is 16 bytes" in Base64
        assertThrows(IllegalArgumentException.class, () -> badCodec.init(params));
    }

    @Test
    void missingKeyThrowsIllegalState() {
        AesGcmCodec noKeyCodec = new AesGcmCodec();
        assertThrows(IllegalStateException.class, () -> noKeyCodec.init(new HashMap<>()));
    }

    @Test
    void uninitializedCodecThrowsOnEncode() {
        AesGcmCodec uninit = new AesGcmCodec();
        assertThrows(IllegalStateException.class, () -> uninit.encode("anything"));
    }

    // ------------------------------------------------------------------
    // Key generation sanity
    // ------------------------------------------------------------------

    @Test
    void generateKeyProduces32Bytes() throws Exception {
        String b64 = AesGcmCodec.generateBase64Key();
        byte[] raw = java.util.Base64.getDecoder().decode(b64);
        assertEquals(32, raw.length, "AES-256 key must be 32 bytes");
    }

    @Test
    void twoGeneratedKeysAreDifferent() throws Exception {
        assertNotEquals(
            AesGcmCodec.generateBase64Key(),
            AesGcmCodec.generateBase64Key()
        );
    }
}
