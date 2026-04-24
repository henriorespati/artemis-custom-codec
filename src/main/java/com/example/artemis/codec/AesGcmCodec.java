package com.example.artemis.codec;

import org.apache.activemq.artemis.utils.SensitiveDataCodec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Logger;

public class AesGcmCodec implements SensitiveDataCodec<String> {

    private static final Logger LOG = Logger.getLogger(AesGcmCodec.class.getName());

    // ------------------------------------------------------------------ //
    //  Constants                                                         //
    // ------------------------------------------------------------------ //

    private static final String ALGORITHM        = "AES";
    private static final String TRANSFORMATION   = "AES/GCM/NoPadding";
    private static final int    GCM_IV_LENGTH    = 12;   // 96-bit nonce
    private static final int    GCM_TAG_BITS     = 128;  // 16-byte auth tag
    private static final int    AES_KEY_BITS     = 256;
    private static final int    AES_KEY_BYTES    = AES_KEY_BITS / 8;

    /** Environment variable name for the Base64-encoded AES key. */
    public static final String ENV_KEY_VAR    = "ARTEMIS_CODEC_KEY";
    /** System property name for the Base64-encoded AES key. */
    public static final String SYSPROP_KEY    = "artemis.codec.key";

    private static final SecureRandom RANDOM = new SecureRandom();

    // ------------------------------------------------------------------ //
    //  State                                                             //
    // ------------------------------------------------------------------ //

    private SecretKey secretKey;

    // ------------------------------------------------------------------ //
    //  SensitiveDataCodec lifecycle                                      //
    // ------------------------------------------------------------------ //

    /**
     * Called by Artemis immediately after instantiation.
     *
     * @param params key/value pairs from the {@code <password-codec>} configuration string.
     */
    @Override
    public void init(Map<String, String> params) {
        secretKey = resolveKey(params);
        LOG.info("[AesGcmCodec] Initialized successfully.");
    }

    /**
     * Encodes (masks) a plaintext password into a Base64 string.
     *
     * @param secret the plaintext password
     * @return Base64-encoded ciphertext (IV prepended)
     */
    @Override
    public String encode(Object secret) throws Exception {
        requireKey();
        byte[] plaintext = secret.toString().getBytes(StandardCharsets.UTF_8);

        byte[] iv = newIv();
        Cipher cipher = buildCipher(Cipher.ENCRYPT_MODE, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Wire format: IV || ciphertext+GCM-tag
        ByteBuffer buf = ByteBuffer.allocate(GCM_IV_LENGTH + ciphertext.length);
        buf.put(iv);
        buf.put(ciphertext);
        return Base64.getEncoder().encodeToString(buf.array());
    }

    /**
     * Decodes (unmasks) a Base64 masked password back to plaintext.
     *
     * @param mask the Base64-encoded masked value (without the {@code ENC()} wrapper)
     * @return the original plaintext password
     */
    @Override
    public String decode(Object mask) throws Exception {
        requireKey();
        byte[] decoded = Base64.getDecoder().decode(mask.toString().trim());

        if (decoded.length <= GCM_IV_LENGTH) {
            throw new IllegalArgumentException(
                "[AesGcmCodec] Masked value is too short to contain a valid IV.");
        }

        byte[] iv         = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(decoded, GCM_IV_LENGTH, decoded.length);

        Cipher cipher = buildCipher(Cipher.DECRYPT_MODE, iv);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Verifies a candidate plaintext against a previously encoded value.
     * Used by PropertiesLoginModule for password verification.
     *
     * @param candidate   the plaintext to test
     * @param encodedValue the stored masked value
     * @return {@code true} if the candidate decodes to the same plaintext
     */
    @Override
    public boolean verify(char[] candidate, String encodedValue) {
        try {
            String decoded = decode(encodedValue);
            return decoded.equals(new String(candidate));
        } catch (Exception e) {
            LOG.warning("[AesGcmCodec] verify() failed: " + e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------ //
    //  Internal helpers                                                  //
    // ------------------------------------------------------------------ //

    private Cipher buildCipher(int mode, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(mode, secretKey, spec);
        return cipher;
    }

    private static byte[] newIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);
        return iv;
    }

    private void requireKey() {
        if (secretKey == null) {
            throw new IllegalStateException(
                "[AesGcmCodec] Codec not initialized — init() was not called or key resolution failed.");
        }
    }

    // ------------------------------------------------------------------ //
    //  Key resolution                                                    //
    // ------------------------------------------------------------------ //

    /**
     * Resolves the AES key using the priority chain documented in the class Javadoc.
     */
    static SecretKey resolveKey(Map<String, String> params) {
        // 1. Key file
        if (params != null && params.containsKey("key-location")) {
            String location = params.get("key-location").trim();
            LOG.info("[AesGcmCodec] Loading key from file: " + location);
            return loadKeyFromFile(location);
        }

        // 2. Inline key param
        if (params != null && params.containsKey("key")) {
            LOG.info("[AesGcmCodec] Using inline key from configuration.");
            return decodeBase64Key(params.get("key").trim());
        }

        // 3. Environment variable
        String envKey = System.getenv(ENV_KEY_VAR);
        if (envKey != null && !envKey.isBlank()) {
            LOG.info("[AesGcmCodec] Using key from environment variable " + ENV_KEY_VAR + ".");
            return decodeBase64Key(envKey.trim());
        }

        // 4. System property
        String sysPropKey = System.getProperty(SYSPROP_KEY);
        if (sysPropKey != null && !sysPropKey.isBlank()) {
            LOG.info("[AesGcmCodec] Using key from system property " + SYSPROP_KEY + ".");
            return decodeBase64Key(sysPropKey.trim());
        }

        throw new IllegalStateException(
            "[AesGcmCodec] No AES key found. Provide it via: " +
            "(1) key-location=<path> param, " +
            "(2) key=<base64> param, " +
            "(3) env var " + ENV_KEY_VAR + ", or " +
            "(4) system property -D" + SYSPROP_KEY);
    }

    private static SecretKey loadKeyFromFile(String path) {
        try {
            String line = Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8)
                               .stream()
                               .filter(l -> !l.isBlank())
                               .findFirst()
                               .orElseThrow(() -> new IllegalArgumentException(
                                   "Key file is empty: " + path));
            return decodeBase64Key(line.trim());
        } catch (Exception e) {
            throw new IllegalStateException("[AesGcmCodec] Failed to read key file: " + path, e);
        }
    }

    private static SecretKey decodeBase64Key(String base64) {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        if (keyBytes.length != AES_KEY_BYTES) {
            throw new IllegalArgumentException(
                "[AesGcmCodec] AES-256 requires a 32-byte key. Got " + keyBytes.length + " bytes. " +
                "Generate one with: CodecTool --generate-key");
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // ------------------------------------------------------------------ //
    //  Key generation utility (called from CodecTool)                    //
    // ------------------------------------------------------------------ //

    /**
     * Generates a new random AES-256 key and returns it Base64-encoded.
     * Intended for use during initial setup only.
     */
    public static String generateBase64Key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(AES_KEY_BITS, RANDOM);
        return Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
    }
}
