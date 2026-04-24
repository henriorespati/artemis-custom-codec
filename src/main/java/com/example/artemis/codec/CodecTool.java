package com.example.artemis.codec;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class CodecTool {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        String mode         = null;
        String password     = null;
        String maskedValue  = null;
        String keyLocation  = null;
        String inlineKey    = null;
        String outFile      = null;

        // Simple arg parser
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
                String b64Key = AesGcmCodec.generateBase64Key();
                if (outFile != null) {
                    Files.write(Paths.get(outFile), b64Key.getBytes(StandardCharsets.UTF_8));
                    // Restrict permissions on Unix systems
                    File f = new File(outFile);
                    f.setReadable(false, false);
                    f.setReadable(true, true);   // owner read
                    f.setWritable(false, false);
                    f.setWritable(true, true);   // owner write
                    System.out.println("Key written to: " + outFile);
                } else {
                    System.out.println("Generated AES-256 key (Base64):");
                    System.out.println(b64Key);
                }
                break;
            }

            case "mask": {
                if (password == null) {
                    System.err.println("--password is required for --mask");
                    System.exit(1);
                }
                AesGcmCodec codec = buildCodec(keyLocation, inlineKey);
                String masked = codec.encode(password);
                System.out.println("Masked value (use inside ENC(...)):");
                System.out.println(masked);
                System.out.println("\nIn broker.xml / login.config:");
                System.out.println("  ENC(" + masked + ")");
                break;
            }

            case "verify": {
                if (password == null || maskedValue == null) {
                    System.err.println("--password and --masked are required for --verify");
                    System.exit(1);
                }
                AesGcmCodec codec = buildCodec(keyLocation, inlineKey);
                String decoded = codec.decode(maskedValue);
                boolean match  = decoded.equals(password);
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

    private static AesGcmCodec buildCodec(String keyLocation, String inlineKey) throws Exception {
        Map<String, String> params = new HashMap<>();
        if (keyLocation != null) params.put("key-location", keyLocation);
        if (inlineKey   != null) params.put("key", inlineKey);
        AesGcmCodec codec = new AesGcmCodec();
        codec.init(params);
        return codec;
    }

    private static void printUsage() {
        System.out.println(
            "Artemis AES-256-GCM Codec Tool\n" +
            "\n" +
            "Modes:\n" +
            "  --generate-key            Generate a new AES-256 key\n" +
            "    [--out <path>]          Write the key to a file (recommended)\n" +
            "\n" +
            "  --mask                    Mask (encrypt) a plaintext password\n" +
            "    --password <value>      The plaintext password to mask\n" +
            "    Key source (one of):\n" +
            "      --key-location <path> Path to Base64-encoded key file\n" +
            "      --key <base64>        Inline Base64-encoded key\n" +
            "\n" +
            "  --verify                  Verify a masked value decodes correctly\n" +
            "    --password <value>      The expected plaintext\n" +
            "    --masked <value>        The masked value to verify\n" +
            "    Key source (same as --mask)\n" +
            "\n" +
            "Environment / System property alternatives to --key:\n" +
            "  ARTEMIS_CODEC_KEY         env var with Base64 key\n" +
            "  -Dartemis.codec.key       system property with Base64 key\n"
        );
    }
}
