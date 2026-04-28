package com.example.artemis.codec;

import org.apache.activemq.artemis.utils.SensitiveDataCodec;

import javax.crypto.SecretKey;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Artemis {@link SensitiveDataCodec} implementation using AES-256-GCM.
 *
 * <p>This class is intentionally thin: it implements the Artemis SPI and
 * delegates all cryptographic work to {@link AesGcmCrypto}, which has no
 * broker dependency and can be used standalone by {@link CodecTool}.
 *
 * <h2>broker.xml</h2>
 * <pre>{@code
 * <password-codec>
 *     com.example.artemis.codec.AesGcmCodec;key-location=/etc/artemis/codec.key
 * </password-codec>
 *
 * <!-- notsecret -->
 * <cluster-password>ENC(masked_value_here)</cluster-password>
 * }</pre>
 *
 * <h2>Key resolution order</h2>
 * <ol>
 *   <li>{@code key-location=<path>} init param — path to Base64-encoded key file</li>
 *   <li>{@code key=<base64>} init param — inline key (dev only)</li>
 *   <li>Environment variable {@code ARTEMIS_CODEC_KEY}</li>
 *   <li>System property {@code -Dartemis.codec.key}</li>
 * </ol>
 */
public class AesGcmCodec implements SensitiveDataCodec<String> {

    private static final Logger LOG = Logger.getLogger(AesGcmCodec.class.getName());

    private SecretKey secretKey;

    @Override
    public void init(Map<String, String> params) {
        secretKey = AesGcmCrypto.resolveKey(params);
        LOG.info("[AesGcmCodec] Initialized successfully.");
    }

    @Override
    public String encode(Object secret) throws Exception {
        requireKey();
        return AesGcmCrypto.encrypt(secret.toString(), secretKey);
    }

    @Override
    public String decode(Object mask) throws Exception {
        requireKey();
        return AesGcmCrypto.decrypt(mask.toString(), secretKey);
    }

    @Override
    public boolean verify(char[] candidate, String encodedValue) {
        try {
            return AesGcmCrypto.decrypt(encodedValue, secretKey).equals(new String(candidate));
        } catch (Exception e) {
            LOG.warning("[AesGcmCodec] verify() failed: " + e.getMessage());
            return false;
        }
    }

    private void requireKey() {
        if (secretKey == null) {
            throw new IllegalStateException(
                "[AesGcmCodec] Codec not initialized — init() was not called.");
        }
    }
}
