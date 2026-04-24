package com.example.artemis.codec;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * CLI helper for managing the AES-256-GCM codec.
 *
 * Depends only on {@link AesGcmCrypto} — no Artemis classes on the classpath
 * are required. Run using the thin JAR:
 *
 * <pre>
 *   # Generate a key
 *   java -cp target/artemis-custom-codec-1.0.0.jar \
 *        com.example.artemis.codec.CodecTool \
 *        --generate-key --out /etc/artemis/codec.key
 *
 *   # Mask a password
 *   java -cp target/artemis-custom-codec-1.0.0.jar \
 *        com.example.artemis.codec.CodecTool \
 *        --mask --key-location /etc/artemis/codec.key --password MySecret
 *
 *   # Verify a masked value
 *   java -cp target/artemis-custom-codec-1.0.0.jar \
 *        com.example.artemis.codec.CodecTool \
 *        --verify --key-location /etc/artemis/codec.key \
 *        --password MySecret --masked BASE64_VALUE
 * </pre>
 */
public class CodecTool {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        String mode        = null;
        String password    = null;
        String maskedValue = null;
        String keyLocation = null;
        String inlineKey   = null;
        String outFile     = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--generate-key": mode = "generate-key"; break;
                case "--mask":         mode = "mask";         break;
                case "--verify":       mode = "verify";       break;
                case "--key-location": keyLocation = args[++i]; break;
                case "--key":          inlineKey   = args[++i]; break;
                case "--password":     password    = args[++i]; break;
                case "--masked":       maskedValue = args[++i]; break;
                case "--out":          outFile     = args[++i]; break;
                default:
                    System.err.println("Unknown argument: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        switch (mode != null ? mode : "") {

            case "generate-key": {
                String b64Key = AesGcmCrypto.generateBase64Key();
                if (outFile != null) {
                    Files.write(Paths.get(outFile), b64Key.getBytes(StandardCharsets.UTF_8));
                    File f = new File(outFile);
                    f.setReadable(false, false); f.setReadable(true, true);
                    f.setWritable(false, false); f.setWritable(true, true);
                    System.out.println("Key written to: " + outFile);
                } else {
                    System.out.println("Generated AES-256 key (Base64):");
                    System.out.println(b64Key);
                }
                break;
            }

            case "mask": {
                if (password == null) { System.err.println("--password is required"); System.exit(1); }
                SecretKey key = AesGcmCrypto.resolveKey(buildParams(keyLocation, inlineKey));
                String masked = AesGcmCrypto.encrypt(password, key);
                System.out.println("Masked value (use inside ENC(...)):");
                System.out.println(masked);
                System.out.println("\nIn broker.xml / login.config:");
                System.out.println("  ENC(" + masked + ")");
                break;
            }

            case "verify": {
                if (password == null || maskedValue == null) {
                    System.err.println("--password and --masked are required");
                    System.exit(1);
                }
                SecretKey key    = AesGcmCrypto.resolveKey(buildParams(keyLocation, inlineKey));
                String decoded   = AesGcmCrypto.decrypt(maskedValue, key);
                boolean match    = decoded.equals(password);
                System.out.println("Decoded : " + decoded);
                System.out.println("Match   : " + match);
                if (!match) System.exit(2);
                break;
            }

            default:
                printUsage();
                System.exit(1);
        }
    }

    private static Map<String, String> buildParams(String keyLocation, String inlineKey) {
        Map<String, String> params = new HashMap<>();
        if (keyLocation != null) params.put("key-location", keyLocation);
        if (inlineKey   != null) params.put("key", inlineKey);
        return params;
    }

    private static void printUsage() {
        System.out.println(
            "Artemis AES-256-GCM Codec Tool\n" +
            "\n" +
            "Modes:\n" +
            "  --generate-key            Generate a new AES-256 key\n" +
            "    [--out <path>]          Write key to a file (recommended)\n" +
            "\n" +
            "  --mask                    Encrypt a plaintext password\n" +
            "    --password <value>\n" +
            "    --key-location <path>   Path to Base64-encoded key file\n" +
            "    --key <base64>          Inline key (dev only)\n" +
            "\n" +
            "  --verify                  Check a masked value decodes correctly\n" +
            "    --password <value>\n" +
            "    --masked <value>\n" +
            "    Key source: same as --mask\n" +
            "\n" +
            "Environment / system property:\n" +
            "  ARTEMIS_CODEC_KEY         env var with Base64 key\n" +
            "  -Dartemis.codec.key       system property with Base64 key\n"
        );
    }
}
