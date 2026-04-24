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
        base64Key = AesGcmCrypto.generateBase64Key();
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
        String masked1 = codec.encode("same-password");
        String masked2 = codec.encode("same-password");
        assertNotEquals(masked1, masked2, "Random IV must make each encoding unique");
    }

    @Test
    void emptyPasswordRoundTrips() throws Exception {
        assertEquals("", codec.decode(codec.encode("")));
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
        char[] chars = masked.toCharArray();
        chars[chars.length - 2] = chars[chars.length - 2] == 'A' ? 'B' : 'A';
        assertThrows(Exception.class, () -> codec.decode(new String(chars)),
            "GCM should reject tampered ciphertext");
    }

    // ------------------------------------------------------------------
    // verify()
    // ------------------------------------------------------------------

    @Test
    void verifyReturnsTrueForMatchingPassword() throws Exception {
        String password = "correct-horse-battery-staple";
        assertTrue(codec.verify(password.toCharArray(), codec.encode(password)));
    }

    @Test
    void verifyReturnsFalseForWrongPassword() throws Exception {
        assertFalse(codec.verify("wrong".toCharArray(), codec.encode("correct")));
    }

    // ------------------------------------------------------------------
    // Key resolution (via AesGcmCrypto)
    // ------------------------------------------------------------------

    @Test
    void keyFromFileResolvesCorrectly(@TempDir Path tempDir) throws Exception {
        Path keyFile = tempDir.resolve("codec.key");
        Files.writeString(keyFile, base64Key);

        AesGcmCodec fileCodec = new AesGcmCodec();
        Map<String, String> params = new HashMap<>();
        params.put("key-location", keyFile.toString());
        fileCodec.init(params);

        assertEquals("hello", fileCodec.decode(fileCodec.encode("hello")));
    }

    @Test
    void wrongKeySizeThrowsIllegalArgument() {
        AesGcmCodec badCodec = new AesGcmCodec();
        Map<String, String> params = new HashMap<>();
        params.put("key", "dGhpcyBpcyAxNiBieXRlcw=="); // 16 bytes — not AES-256
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
    // Key generation (via AesGcmCrypto)
    // ------------------------------------------------------------------

    @Test
    void generateKeyProduces32Bytes() throws Exception {
        byte[] raw = java.util.Base64.getDecoder().decode(AesGcmCrypto.generateBase64Key());
        assertEquals(32, raw.length);
    }

    @Test
    void twoGeneratedKeysAreDifferent() throws Exception {
        assertNotEquals(AesGcmCrypto.generateBase64Key(), AesGcmCrypto.generateBase64Key());
    }
}
