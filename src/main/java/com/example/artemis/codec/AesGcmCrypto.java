package com.example.artemis.codec;

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

/**
 * Pure-JCE AES-256-GCM crypto helper.
 *
 * No Artemis types referenced — safe to run in any JVM without the broker
 * on the classpath. Both {@link AesGcmCodec} (broker runtime) and
 * {@link CodecTool} (CLI) delegate here.
 */
public final class AesGcmCrypto {

    private static final Logger LOG = Logger.getLogger(AesGcmCrypto.class.getName());

    static final String ALGORITHM      = "AES";
    static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static final int    GCM_IV_LENGTH  = 12;
    static final int    GCM_TAG_BITS   = 128;
    static final int    AES_KEY_BITS   = 256;
    static final int    AES_KEY_BYTES  = AES_KEY_BITS / 8;

    public static final String ENV_KEY_VAR = "ARTEMIS_CODEC_KEY";
    public static final String SYSPROP_KEY = "artemis.codec.key";

    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcmCrypto() {}

    // ------------------------------------------------------------------ //
    //  Encrypt / decrypt                                                   //
    // ------------------------------------------------------------------ //

    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteBuffer buf = ByteBuffer.allocate(GCM_IV_LENGTH + ciphertext.length);
        buf.put(iv);
        buf.put(ciphertext);
        return Base64.getEncoder().encodeToString(buf.array());
    }

    public static String decrypt(String masked, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(masked.trim());
        if (decoded.length < GCM_IV_LENGTH + (GCM_TAG_BITS / 8)) {
            throw new IllegalArgumentException(
                "[AesGcmCrypto] Masked value too short — expected at least " +
                (GCM_IV_LENGTH + GCM_TAG_BITS / 8) + " bytes after Base64 decode. Empty plaintext produces exactly 28 bytes.");
        }

        // IV is the first GCM_IV_LENGTH bytes
        byte[] iv = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // Use offset-based doFinal to avoid JDK-8254059 (ProviderException wrapping
        // ShortBufferException in GCM engineDoFinal on JDK 15+).
        // Passing the original array with an offset avoids the intermediate copy that
        // triggers the JDK's internal output-buffer miscalculation.
        byte[] plaintext = cipher.doFinal(decoded, GCM_IV_LENGTH, decoded.length - GCM_IV_LENGTH);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ //
    //  Key generation                                                      //
    // ------------------------------------------------------------------ //

    public static String generateBase64Key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(AES_KEY_BITS, RANDOM);
        return Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
    }

    // ------------------------------------------------------------------ //
    //  Key resolution                                                      //
    // ------------------------------------------------------------------ //

    public static SecretKey resolveKey(Map<String, String> params) {
        if (params != null && params.containsKey("key-location")) {
            String location = params.get("key-location").trim();
            LOG.info("[AesGcmCrypto] Loading key from file: " + location);
            return loadKeyFromFile(location);
        }
        if (params != null && params.containsKey("key")) {
            LOG.info("[AesGcmCrypto] Using inline key from configuration.");
            return decodeBase64Key(params.get("key").trim());
        }
        String envKey = System.getenv(ENV_KEY_VAR);
        if (envKey != null && !envKey.isBlank()) {
            LOG.info("[AesGcmCrypto] Using key from environment variable " + ENV_KEY_VAR + ".");
            return decodeBase64Key(envKey.trim());
        }
        String sysPropKey = System.getProperty(SYSPROP_KEY);
        if (sysPropKey != null && !sysPropKey.isBlank()) {
            LOG.info("[AesGcmCrypto] Using key from system property " + SYSPROP_KEY + ".");
            return decodeBase64Key(sysPropKey.trim());
        }
        throw new IllegalStateException(
            "[AesGcmCrypto] No AES key found. Provide one via: " +
            "(1) key-location=<path>, (2) key=<base64>, " +
            "(3) env " + ENV_KEY_VAR + ", or (4) -D" + SYSPROP_KEY);
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
            throw new IllegalStateException("[AesGcmCrypto] Failed to read key file: " + path, e);
        }
    }

    static SecretKey decodeBase64Key(String base64) {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        if (keyBytes.length != AES_KEY_BYTES) {
            throw new IllegalArgumentException(
                "[AesGcmCrypto] AES-256 requires a 32-byte key. Got " + keyBytes.length +
                " bytes. Generate one with: CodecTool --generate-key");
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}
