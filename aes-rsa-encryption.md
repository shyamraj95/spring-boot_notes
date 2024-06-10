###  Step-by-Step Plan

1. **Define custom properties for RSA key paths:**
   - Define custom properties in `application.properties`.
   - Use `@ConfigurationProperties` and `@EnableConfigurationProperties` to bind these properties.

2. **Implement AES CBC Mode:**
   - Create `AESCryptoService` Interface.
   - Implement methods for generating random key and IV.
   - Implement methods for encryption and decryption using AES in CBC mode that accept strings for keys and IVs.

3. **Implement RSA Encryption:**
   - Create `RSACryptoService` Interface.
   - Implement methods for generating PEM format private and public keys.
   - Implement methods for encryption and decryption using RSA keys.

4. **Create CryptoService Interface:**
   - Define methods for both AES and RSA operations.

5. **Service Implementation:**
   - Create a `CryptoServiceImpl` class that implements the `CryptoService` interface.

6. **Controller:**
   - Create a `CryptoController` to expose endpoints for testing the functionality.

### Implementation

#### 1. Define custom properties for RSA key paths

**application.properties:**
```properties
rsa.private.key.path=/path/to/private_key.pem
rsa.public.key.path=/path/to/public_key.pem
```

**CryptoProperties.java:**
```java
package com.example.crypto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "rsa")
public class CryptoProperties {
    private String privateKeyPath;
    private String publicKeyPath;

    // Getters and Setters
    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public String getPublicKeyPath() {
        return publicKeyPath;
    }

    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }
}
```

**Application.java (Main Application Class):**
```java
package com.example.crypto;

import com.example.crypto.config.CryptoProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(CryptoProperties.class)
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

#### 2. Implement AES CBC Mode

**AESCryptoService.java:**
```java
package com.example.crypto.service;

public interface AESCryptoService {
    String generateKey() throws NoSuchAlgorithmException;
    String generateIv();
    String encrypt(String input, String key, String iv) throws Exception;
    String decrypt(String cipherText, String key, String iv) throws Exception;
}
```

**AESCryptoServiceImpl.java:**
```java
package com.example.crypto.service.impl;

import com.example.crypto.service.AESCryptoService;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class AESCryptoServiceImpl implements AESCryptoService {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    @Override
    public String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Override
    public String generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    @Override
    public String encrypt(String input, String keyBase64, String ivBase64) throws Exception {
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(keyBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivBase64));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    @Override
    public String decrypt(String cipherText, String keyBase64, String ivBase64) throws Exception {
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(keyBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivBase64));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
}
```

#### 3. Implement RSA Encryption

**RSACryptoService.java:**
```java
package com.example.crypto.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface RSACryptoService {
    KeyPair generateKeyPair() throws Exception;
    PublicKey getPublicKey() throws Exception;
    PrivateKey getPrivateKey() throws Exception;
    String encrypt(String data, PublicKey publicKey) throws Exception;
    String decrypt(String data, PrivateKey privateKey) throws Exception;
    String convertToPEM(PublicKey publicKey);
    String convertToPEM(PrivateKey privateKey);
}
```

**RSACryptoServiceImpl.java:**
```java
package com.example.crypto.service.impl;

import com.example.crypto.config.CryptoProperties;
import com.example.crypto.service.RSACryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class RSACryptoServiceImpl implements RSACryptoService {
    private static final String ALGORITHM = "RSA";

    @Autowired
    private CryptoProperties cryptoProperties;

    @Override
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    @Override
    public PublicKey getPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(cryptoProperties.getPublicKeyPath()));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    @Override
    public PrivateKey getPrivateKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(cryptoProperties.getPrivateKeyPath()));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    @Override
    public String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    @Override
    public String decrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(plainText);
    }

    @Override
    public String convertToPEM(PublicKey publicKey) {
        return "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
    }

    @Override
    public String convertToPEM(PrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----";
    }
}
```

#### 4. Create CryptoService Interface

**CryptoService.java:**
```java
package com.example.crypto.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface CryptoService {
    String generateAESKey() throws Exception;
    String generateIv();
    String encryptAES(String input, String key, String iv) throws Exception;
    String decryptAES(String cipherText, String key, String iv) throws Exception;
    KeyPair generateRSAKeyPair() throws Exception;
    PublicKey getRSAPublicKey() throws Exception;
    PrivateKey getRSAPrivateKey() throws Exception;
    String encryptRSA(String data, PublicKey publicKey) throws Exception;
    String decryptRSA(String data, PrivateKey privateKey) throws Exception;
    String convertRSAPublicKeyToPEM(PublicKey publicKey);
    String convertRSAPrivateKeyToPEM(PrivateKey privateKey);
}
```

#### 5. Service Implementation

**CryptoServiceImpl.java:**
```java
package com.example.crypto.service.impl

;

import com.example.crypto.service.AESCryptoService;
import com.example.crypto.service.CryptoService;
import com.example.crypto.service.RSACryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Service
public class CryptoServiceImpl implements CryptoService {
    private final AESCryptoService aesCryptoService;
    private final RSACryptoService rsaCryptoService;

    @Autowired
    public CryptoServiceImpl(AESCryptoService aesCryptoService, RSACryptoService rsaCryptoService) {
        this.aesCryptoService = aesCryptoService;
        this.rsaCryptoService = rsaCryptoService;
    }

    @Override
    public String generateAESKey() throws Exception {
        return aesCryptoService.generateKey();
    }

    @Override
    public String generateIv() {
        return aesCryptoService.generateIv();
    }

    @Override
    public String encryptAES(String input, String key, String iv) throws Exception {
        return aesCryptoService.encrypt(input, key, iv);
    }

    @Override
    public String decryptAES(String cipherText, String key, String iv) throws Exception {
        return aesCryptoService.decrypt(cipherText, key, iv);
    }

    @Override
    public KeyPair generateRSAKeyPair() throws Exception {
        return rsaCryptoService.generateKeyPair();
    }

    @Override
    public PublicKey getRSAPublicKey() throws Exception {
        return rsaCryptoService.getPublicKey();
    }

    @Override
    public PrivateKey getRSAPrivateKey() throws Exception {
        return rsaCryptoService.getPrivateKey();
    }

    @Override
    public String encryptRSA(String data, PublicKey publicKey) throws Exception {
        return rsaCryptoService.encrypt(data, publicKey);
    }

    @Override
    public String decryptRSA(String data, PrivateKey privateKey) throws Exception {
        return rsaCryptoService.decrypt(data, privateKey);
    }

    @Override
    public String convertRSAPublicKeyToPEM(PublicKey publicKey) {
        return rsaCryptoService.convertToPEM(publicKey);
    }

    @Override
    public String convertRSAPrivateKeyToPEM(PrivateKey privateKey) {
        return rsaCryptoService.convertToPEM(privateKey);
    }
}
```

#### 6. Controller

**CryptoController.java:**
```java
package com.example.crypto.controller;

import com.example.crypto.service.CryptoService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.PrivateKey;
import java.security.PublicKey;

@RestController
public class CryptoController {
    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @GetMapping("/aes/encrypt")
    public String encryptAES(@RequestParam String input) throws Exception {
        String key = cryptoService.generateAESKey();
        String iv = cryptoService.generateIv();
        return cryptoService.encryptAES(input, key, iv);
    }

    @GetMapping("/aes/decrypt")
    public String decryptAES(@RequestParam String cipherText, @RequestParam String key, @RequestParam String iv) throws Exception {
        return cryptoService.decryptAES(cipherText, key, iv);
    }

    @GetMapping("/rsa/encrypt")
    public String encryptRSA(@RequestParam String data) throws Exception {
        PublicKey publicKey = cryptoService.getRSAPublicKey();
        return cryptoService.encryptRSA(data, publicKey);
    }

    @GetMapping("/rsa/decrypt")
    public String decryptRSA(@RequestParam String data) throws Exception {
        PrivateKey privateKey = cryptoService.getRSAPrivateKey();
        return cryptoService.decryptRSA(data, privateKey);
    }
}
```
