# Artemis AES-256-GCM Custom Password Codec

A production-ready custom `SensitiveDataCodec` for Apache ActiveMQ Artemis / Red Hat AMQ Broker
that replaces the deprecated default two-way codec with **AES-256-GCM** authenticated encryption.

---

## Why AES-256-GCM?

| Property | Default Codec (two-way) | This codec |
|---|---|---|
| Algorithm | Blowfish / legacy | AES-256-GCM |
| Authenticated | No | Yes (tamper-evident) |
| IV/nonce | Static | Random per encode |
| Deprecated | Yes | No |

---

## Project layout

```
src/main/java/com/example/artemis/codec/
  AesGcmCodec.java        ← The SensitiveDataCodec implementation
  CodecTool.java          ← CLI helper for key generation & masking

src/main/resources/META-INF/services/
  org.apache.activemq.artemis.utils.SensitiveDataCodec   ← SPI registration

src/test/java/com/example/artemis/codec/
  AesGcmCodecTest.java    ← Unit tests
```

---

## Build

```bash
mvn clean package
```

This produces two JARs in `target/`:
- `artemis-custom-codec-1.0.0.jar`          ← thin jar (needs Artemis on classpath)
- `artemis-custom-codec-1.0.0-all-deps.jar` ← fat jar (self-contained, easier to deploy)

---

## Deploying to the broker

Copy the JAR into the broker's lib directory so it is on the classpath:

```bash
cp target/artemis-custom-codec-1.0.0.jar $ARTEMIS_INSTANCE/lib/
```

> **AMQ Broker on RHEL / Podman:** mount or copy the JAR into the container and
> reference it via the `lib/` directory of the broker instance.

---

## Setup workflow

### Step 1 — Generate a key

```bash
java -cp target/artemis-custom-codec-1.0.0.jar \
     com.example.artemis.codec.CodecTool \
     --generate-key --out /etc/artemis/codec.key

# Restrict permissions
chmod 600 /etc/artemis/codec.key
```

> The file contains a single line: a Base64-encoded 32-byte (256-bit) AES key.
> Keep this file secret. Do **not** commit it to version control.

### Step 2 — Mask your passwords

```bash
java -cp target/artemis-custom-codec-1.0.0.jar \
     com.example.artemis.codec.CodecTool \
     --mask \
     --key-location /etc/artemis/codec.key \
     --password "MyBrokerPassword"

# Output:
# Masked value (use inside ENC(...)):
# dGhpcyBpcyBhbiBleGFtcGxl...
#
# In broker.xml / login.config:
#   ENC(dGhpcyBpcyBhbiBleGFtcGxl...)
```

### Step 3 — Configure broker.xml

```xml
<configuration>

    <!-- Tell Artemis to use the custom codec -->
    <password-codec>
        com.example.artemis.codec.AesGcmCodec;key-location=/etc/artemis/codec.key
    </password-codec>

    <!-- Wrap every masked password in ENC() -->
    <cluster-password>ENC(dGhpcyBpcyBhbiBleGFtcGxl...)</cluster-password>

</configuration>
```

### Step 4 — SSL/TLS passwords (acceptors & connectors)

```xml
<acceptors>
    <acceptor name="artemis">
        tcp://0.0.0.0:61616?sslEnabled=true;
        keyStorePassword=ENC(maskedKeyStorePassword);
        trustStorePassword=ENC(maskedTrustStorePassword)
    </acceptor>
</acceptors>
```

### Step 5 — bootstrap.xml

```xml
<web path="web" rootRedirectLocation="console">
    <binding name="artemis"
             uri="https://localhost:8443"
             keyStorePassword="ENC(maskedKeyStorePassword)"
             trustStorePassword="ENC(maskedTrustStorePassword)"
             passwordCodec="com.example.artemis.codec.AesGcmCodec;key-location=/etc/artemis/codec.key">
        <app name="console" url="console" war="console.war"/>
    </binding>
</web>
```

### Step 6 — login.config (JAAS PropertiesLoginModule)

```
PropertiesLoginWithCustomCodec {
    org.apache.activemq.artemis.spi.core.security.jaas.PropertiesLoginModule required
        org.apache.activemq.jaas.properties.user="users.properties"
        org.apache.activemq.jaas.properties.role="roles.properties"
        org.apache.activemq.jaas.properties.password.codec="com.example.artemis.codec.AesGcmCodec;key-location=/etc/artemis/codec.key";
};
```

---

## Key resolution priority

The codec resolves the AES key in this order:

| Priority | Source | Configuration |
|---|---|---|
| 1 (best) | Key file | `key-location=/path/to/codec.key` init param |
| 2 | Inline key | `key=BASE64_KEY` init param |
| 3 | Environment variable | `ARTEMIS_CODEC_KEY=BASE64_KEY` |
| 4 | System property | `-Dartemis.codec.key=BASE64_KEY` |

> **Recommended:** Use `key-location` pointing to a file owned by the broker OS user
> with `chmod 600`. The key never appears in any config file this way.

---

## Running tests

```bash
mvn test
```

Tests cover: round-trip encode/decode, random IV uniqueness, GCM tamper detection,
`verify()`, key-from-file, wrong key size rejection, and key generation.

---

## Wire format

```
Base64( IV[12 bytes] || AES-GCM-ciphertext+tag )
```

- **IV**: 12-byte random nonce generated fresh for every `encode()` call
- **Tag**: 128-bit GCM authentication tag appended by the JCE (inside `ciphertext`)
- The broker stores only the Base64 string; Artemis wraps it in `ENC(...)`
