# TheIceNet Cryptography library

TheIceNet Cryptography is a library which makes easy to develop cryptography-based, production-grade Spring Boot applications. 

The library homogenises how to use and invoke the similar families of cryptography primitives. TheIceNet Cryptography makes the consumer code agnostic from the underlying cryptography algorithm used, so it makes easy to switch the cryptography configuration or even the cryptography algorithm without affecting the consuming code.

TheIceNet Cryptography fully integrates with Spring Boot, making it easy and seamless to use cryptography in any Spring Boot based applications.  

## Table of contents

* TheIceNet Cryptography structure
    * [Modules](#modules)
* TheIceNet Cryptography supported algorithms
    * [Symmetric cryptography supported algorithms](#symmetric-cryptography-supported-algorithms)
    * [Asymmetric cryptography supported algorithms](#asymmetric-cryptography-supported-algorithms)
    * [Hashing supported algorithms](#hashing-supported-algorithms)
    * [Password Based Key Derivation (PBKD) supported algorithms](#password-based-key-derivation-supported-algorithms)
    * [Random data generation support](#random-data-generation-support)
* Getting Started
    * [TheIceNet Cryptography library requirements](#theicenet-cryptography-library-requirements)
    * [Installing TheIceNet Cryptography library](#installing-theicenet-cryptography-library)
    * [Building TheIceNet Cryptography library](#building-theicenet-cryptography-library)
    * [Thread Safety](#thread-safety)
* [How to use TheIceNet Cryptography library](#how-to-use-theicenet-cryptography-library)
    * Key generation
        * Symmetric cryptography
            * [Generate random AES secret key](#generate-random-aes-secret-key)
        * Asymmetric cryptography
            * [Generate random RSA key pair](#generate-random-rsa-key-pair)
            * [Generate random DSA key pair](#generate-random-dsa-key-pair)
            * [Generate random ECDSA key pair](#generate-random-ecdsa-key-pair)
            * [Generate random ECDH key pair](#generate-random-ecdh-key-pair)
    * Key agreement over an insecure channel
        * [Key agreement with ECDH](#key-agreement-with-ecdh)
    * Password Based Key Derivation (PBKD)
        * [Password based key derivation with PBKDF2 from string/byte array](#password-based-key-derivation-with-pbkdf2-from-string-or-byte-array)
        * [Password based key derivation with Scrypt from string/byte array](#password-based-key-derivation-with-scrypt-from-string-or-byte-array)
        * [Password based key derivation with Argon2 from string/byte array](#password-based-key-derivation-with-argon2-from-string-or-byte-array)
    * Encrypt / Decrypt
        * Symmetric cryptography
            * [Encrypt/Decrypt byte array/stream with AES and ECB block mode of operation](#encrypt-and-decrypt-byte-array-or-stream-with-aes-and-ecb-block-mode-of-operation)
            * [Encrypt/Decrypt byte array/stream with AES and IV based block mode of operation](#encrypt-and-decrypt-byte-array-or-stream-with-aes-and-iv-based-block-mode-of-operation)
        * Asymmetric cryptography        
            * [Encrypt/Decrypt with RSA](#encrypt-and-decrypt-with-rsa)
    * Signature generation
        * [Generate/Verify signature for a byte array/stream with RSA](#generate-and-verify-signature-for-a-byte-array-or-stream-with-rsa)
        * [Generate/Verify signature for a byte array/stream with DSA](#generate-and-verify-signature-for-a-byte-array-or-stream-with-dsa)
        * [Generate/Verify signature for a byte array/stream with ECDSA](#generate-and-verify-signature-for-a-byte-array-or-stream-with-ecdsa)
    * Hash generation
        * [Generate hash of byte array/stream](#generate-hash-of-byte-array-or-stream)
    * Message authentication code generation
        * [MAC generation](#mac-generation)
    * Random data generation 
        * [Generate random initialisation vector](#generate-random-initialisation-vector)
        * [Generate random salt](#generate-random-salt)
       
## Modules

There are four modules in TheIceNet Cryptography library, here is a quick overview of them:

* **theicenet-cryptography-spring-boot-starter** -> Spring Boot starter module which provides TheIceNet Cryptography library with full and seamless integration in any Spring Boot application.

* **theicenet-cryptography-module** -> Main cryptography module which provides with the foundations and cryptography components. Worth to mention that TheIceNet Cryptography library can be enabled as well in vanilla Java application by just adding this module to our package manager. (The use of TheIceNet Cryptography library in vanilla Java applications is not included in this documentation) 
    
* **theicenet-cryptography-acceptance-tests** -> TheIceNet Cryptography library acceptance tests.

* **theicenet-cryptography-test-support** -> Utilities to help and support on different levels of the library automatic testing.
   
## Symmetric cryptography supported algorithms

TheIceNet Cryptography library can work with the next symmetric cryptography algorithms,

- **Key Generation**
    - AES

- **Encrypt / Decrypt**
    - AES
        - Block Modes of Operation (non IV based): ECB
        - Block Modes of Operation (IV based): CBC, CFB, OFB, CTR 
  
- **MAC generation**
    - HMAC
        - HmacSHA1
        - HmacSHA224
        - HmacSHA256
        - HmacSHA384
        - HmacSHA512
        
## Asymmetric cryptography supported algorithms

TheIceNet Cryptography library can work with the next asymmetric cryptography algorithms,
         
- **Key Generation**
    - RSA
    - DSA
    - ECDSA
        - Elliptic curve primeXXXv1 -> 192 bits, 239 bits and 256 bits
        - Elliptic curve primeXXXv2 -> 192 bits and 239 bits
        - Elliptic curve primeXXXv3 -> 192 bits and 239 bits
        - Elliptic curve secpXXXk1 -> 192 bits, 224 bits and 256 bits
        - Elliptic curve secpXXXr1 -> 192 bits, 224 bits, 256 bits, 384 bits and 521 bits
        - Elliptic curve P_XXX -> 224 bits, 256 bits, 384 bits and 521 bits
        - Elliptic curve c2pnbXXXv1 -> 163 bits
        - Elliptic curve c2pnbXXXv2 -> 163 bits
        - Elliptic curve c2pnbXXXv3 -> 163 bits
        - Elliptic curve c2pnbXXXw1 -> 176 bits, 208 bits, 272 bits, 304 bits and 368 bits
        - Elliptic curve c2tnbXXXv1 -> 191 bits, 239 bits and 359 bits
        - Elliptic curve c2tnbXXXv2 -> 191 bits and 239 bits
        - Elliptic curve c2tnbXXXv3 -> 191 bits and 239 bits
        - Elliptic curve c2tnbXXXr1 -> 431 bits
        - Elliptic curve sectXXXk1 -> 163 bits, 233 bits, 239 bits, 283 bits, 409 bits and 571 bits
        - Elliptic curve sectXXXr1 -> 163 bits, 193 bits, 233 bits, 283 bits, 409 bits and 571 bits
        - Elliptic curve sectXXXr2 -> 163 bits and 193 bits
        - Elliptic curve B_XXX -> 163 bits, 233 bits, 283 bits, 409 bits and 571 bits
        - Elliptic curve brainpoolpXXXr1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits
        - Elliptic curve brainpoolpXXXt1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits
    - ECDH
        - Elliptic curve primeXXXv1 -> 192 bits, 239 bits and 256 bits
        - Elliptic curve primeXXXv2 -> 192 bits and 239 bits
        - Elliptic curve primeXXXv3 -> 192 bits and 239 bits
        - Elliptic curve secpXXXk1 -> 192 bits, 224 bits and 256 bits
        - Elliptic curve secpXXXr1 -> 192 bits, 224 bits, 256 bits, 384 bits and 521 bits
        - Elliptic curve P_XXX -> 224 bits, 256 bits, 384 bits and 521 bits
        - Elliptic curve c2pnbXXXv1 -> 163 bits
        - Elliptic curve c2pnbXXXv2 -> 163 bits
        - Elliptic curve c2pnbXXXv3 -> 163 bits
        - Elliptic curve c2pnbXXXw1 -> 176 bits, 208 bits, 272 bits, 304 bits and 368 bits
        - Elliptic curve c2tnbXXXv1 -> 191 bits, 239 bits and 359 bits
        - Elliptic curve c2tnbXXXv2 -> 191 bits and 239 bits
        - Elliptic curve c2tnbXXXv3 -> 191 bits and 239 bits
        - Elliptic curve c2tnbXXXr1 -> 431 bits
        - Elliptic curve sectXXXk1 -> 163 bits, 233 bits, 239 bits, 283 bits, 409 bits and 571 bits
        - Elliptic curve sectXXXr1 -> 163 bits, 193 bits, 233 bits, 283 bits, 409 bits and 571 bits
        - Elliptic curve sectXXXr2 -> 163 bits and 193 bits
        - Elliptic curve B_XXX -> 163 bits, 233 bits, 283 bits, 409 bits and 571 bits
        - Elliptic curve brainpoolpXXXr1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits
        - Elliptic curve brainpoolpXXXt1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits
    
- **Key agreement**
    - ECDH
    
- **Encrypt / Decrypt**
    - RSA
        - NoPadding
        - PKCS1Padding
        - OAEPWithMD5AndMGF1Padding
        - OAEPWithSHA1AndMGF1Padding
        - OAEPWithSHA224AndMGF1Padding
        - OAEPWithSHA256AndMGF1Padding
        - OAEPWithSHA384AndMGF1Padding
        - OAEPWithSHA512AndMGF1Padding
        - OAEPWithSHA3_224AndMGF1Padding
        - OAEPWithSHA3_256AndMGF1Padding
        - OAEPWithSHA3_384AndMGF1Padding
        - OAEPWithSHA3_512AndMGF1Padding
        - ISO9796_1Padding
      
- **Signature generation/verification**
    - RSA
        - NonewithRSA
        - RIPEMD128withRSA
        - RIPEMD160withRSA
        - RIPEMD256withRSA
        - SHA1withRSA
        - SHA224withRSA
        - SHA256withRSA
        - SHA384withRSA
        - SHA512withRSA
        - SHA3_224withRSA
        - SHA3_256withRSA
        - SHA3_384withRSA
        - SHA3_512withRSA
        - SHA1withRSAandMGF1
        - SHA256withRSAandMGF1
        - SHA384withRSAandMGF1
        - SHA512withRSAandMGF1
        - SHA1WithRSA_PSS
        - SHA224withRSA_PSS
        - SHA256withRSA_PSS
        - SHA384withRSA_PSS
        - SHA512withRSA_PSS
    - DSA
        - NONEwithDSA
        - SHA1withDSA
        - SHA224withDSA
        - SHA256withDSA
        - SHA384withDSA
        - SHA512withDSA
        - SHA3_224withDSA
        - SHA3_256withDSA
        - SHA3_384withDSA
        - SHA3_512withDSA
    - ECDSA
        - NoneWithECDSA
        - RIPEMD160withECDSA
        - SHA1withECDSA
        - SHA224withECDSA
        - SHA256withECDSA
        - SHA384withECDSA
        - SHA512withECDSA
        - SHA3_224withECDSA
        - SHA3_256withECDSA
        - SHA3_384withECDSA
        - SHA3_512withECDSA
        
## Hashing supported algorithms
    
TheIceNet Cryptography library can work with the next hashing algorithms,

- **Hash generation**
    - MD5
    - SHA_1
    - SHA_224
    - SHA_256
    - SHA_384
    - SHA_512
    - SHA3_224
    - SHA3_256
    - SHA3_384
    - SHA3_512
    - KECCAK_224
    - KECCAK_256
    - KECCAK_288
    - KECCAK_384
    - KECCAK_512
    - Whirlpool
    - Tiger
    - SM3
      
## Password Based Key Derivation supported algorithms 
       
TheIceNet Cryptography library can work with the next PBKD algorithms,

- **Password based key derivation (PBKD)**
    - PBKDF2
        - PBKDF2WithHmac
            - SHA1
            - SHA256
            - SHA512
            - SHA3_256
            - SHA3_512
    - Scrypt
    - Argon2
        - Type
            - ARGON2_D
            - ARGON2_I
            - ARGON2_ID
        - Version
            - ARGON2_VERSION_10
            - ARGON2_VERSION_13
    
## Random data generation support

TheIceNet Cryptography library can generate the next type of random data,
 
- **Random data generation**
    - Initialization Vector (IV) generation
    - Salt generation

## TheIceNet Cryptography library requirements

- [Java 11](https://adoptopenjdk.net) or later
- [Spring Boot 2.0.0](https://spring.io/projects/spring-boot) or later
- [Maven 3.2+](https://maven.apache.org) or [Gradle 4+](https://gradle.org)

## Installing TheIceNet Cryptography library

To enable TheIceNet Cryptography library in a Spring Boot application, we'll just need to add the *theicenet-cryptography-spring-boot-starter* dependency to our package manager. 

In Maven:

```xml
    <dependency>
      <groupId>com.theicenet</groupId>
      <artifactId>theicenet-cryptography-spring-boot-starter</artifactId>
      <version>1.0.1</version>
    </dependency>
```

In Gradle

```groovy
    compile group: 'com.theicenet', name: 'theicenet-cryptography-spring-boot-starter', version: '1.0.1'
```

## Building TheIceNet Cryptography library

TheIceNet Cryptography library uses Maven as building tool. To build the library follow the next steps,

-  Clone the repository
-  Change to the library root folder 
```shell script
cd theicenet-cryptography
```
- Build the library
```shell script
mvn clean install
```

## Thread Safety

All components in the TheIceNet Cryptography library are `unconditionally thread safe`. Any of the components described throughout this documentation can be safely injected in a `@Singleton` scope, and invoked by any number of threads concurrently or consecutively.
 
TheIceNet Cryptography library does not make use of any `shared mutable state`. Because of this, the thread safety provided by the library doesn't require to use any lock or synchronization mechanism at all. This means that TheIceNet Cryptography library does not introduce any penalization in terms of throughput in order to achieve the `unconditionally thread safety`.
 
## How to use TheIceNet Cryptography library

### Generate random AES secret key

```java
import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SymmetricKeyService aesKeyService;

  @Autowired
  public MyComponent(@Qualifier("AESKey") SymmetricKeyService aesKeyService) {
    this.aesKeyService = aesKeyService;
  }

  public void generateSecretKey() {
    // Generate an AES key with 256 bits length
    SecretKey secretKey = aesKeyService.generateKey(256); // RAW format secretKey
  }
}
```

### Generate random RSA key pair

```java
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final AsymmetricKeyService asymmetricKeyService;

  @Autowired
  public MyComponent(@Qualifier("RSAKey") AsymmetricKeyService asymmetricKeyService) {
    this.asymmetricKeyService = asymmetricKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate a key with 1024 bits length
    KeyPair keyPair = asymmetricKeyService.generateKey(1024);
    
    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}
```

### Generate random DSA key pair

```java
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final AsymmetricKeyService asymmetricKeyService;

  @Autowired
  public MyComponent(@Qualifier("DSAKey") AsymmetricKeyService asymmetricKeyService) {
    this.asymmetricKeyService = asymmetricKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate a key with 1024 bits length
    KeyPair keyPair = asymmetricKeyService.generateKey(1024);

    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}
```

### Generate random ECDSA key pair

```java
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final AsymmetricKeyService asymmetricKeyService;

  @Autowired
  public MyComponent(@Qualifier("ECDSAKey") AsymmetricKeyService asymmetricKeyService) {
    this.asymmetricKeyService = asymmetricKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate key with 256 bits length
    KeyPair keyPair = asymmetricKeyService.generateKey(256);

    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}
```

The default curve used is `brainpoolpXXXt1`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdsa:
          curve: secpXXXk1
```

The supported curves and their provided key lengths are,

    - primeXXXv1 -> 192 bits, 239 bits and 256 bits
    - primeXXXv2 -> 192 bits and 239 bits
    - primeXXXv3 -> 192 bits and 239 bits
    - secpXXXk1 -> 192 bits, 224 bits and 256 bits
    - secpXXXr1 -> 192 bits, 224 bits, 256 bits, 384 bits and 521 bits
    - P_XXX -> 224 bits, 256 bits, 384 bits and 521 bits
    - c2pnbXXXv1 -> 163 bits
    - c2pnbXXXv2 -> 163 bits
    - c2pnbXXXv3 -> 163 bits
    - c2pnbXXXw1 -> 176 bits, 208 bits, 272 bits, 304 bits and 368 bits
    - c2tnbXXXv1 -> 191 bits, 239 bits and 359 bits
    - c2tnbXXXv2 -> 191 bits and 239 bits
    - c2tnbXXXv3 -> 191 bits and 239 bits
    - c2tnbXXXr1 -> 431 bits
    - sectXXXk1 -> 163 bits, 233 bits, 239 bits, 283 bits, 409 bits and 571 bits
    - sectXXXr1 -> 163 bits, 193 bits, 233 bits, 283 bits, 409 bits and 571 bits
    - sectXXXr2 -> 163 bits and 193 bits
    - B_XXX -> 163 bits, 233 bits, 283 bits, 409 bits and 571 bits
    - brainpoolpXXXr1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits
    - brainpoolpXXXt1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits

### Generate random ECDH key pair

```java
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final AsymmetricKeyService asymmetricKeyService;

  @Autowired
  public MyComponent(@Qualifier("ECDHKey") AsymmetricKeyService asymmetricKeyService) {
    this.asymmetricKeyService = asymmetricKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate a key with 256 bits length
    KeyPair keyPair = asymmetricKeyService.generateKey(256);

    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}
```

The default curve used is `brainpoolpXXXt1`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdh:
          curve: secpXXXk1
```

The supported curves and their provided key lengths are,

    - primeXXXv1 -> 192 bits, 239 bits and 256 bits
    - primeXXXv2 -> 192 bits and 239 bits
    - primeXXXv3 -> 192 bits and 239 bits
    - secpXXXk1 -> 192 bits, 224 bits and 256 bits
    - secpXXXr1 -> 192 bits, 224 bits, 256 bits, 384 bits and 521 bits
    - P_XXX -> 224 bits, 256 bits, 384 bits and 521 bits
    - c2pnbXXXv1 -> 163 bits
    - c2pnbXXXv2 -> 163 bits
    - c2pnbXXXv3 -> 163 bits
    - c2pnbXXXw1 -> 176 bits, 208 bits, 272 bits, 304 bits and 368 bits
    - c2tnbXXXv1 -> 191 bits, 239 bits and 359 bits
    - c2tnbXXXv2 -> 191 bits and 239 bits
    - c2tnbXXXv3 -> 191 bits and 239 bits
    - c2tnbXXXr1 -> 431 bits
    - sectXXXk1 -> 163 bits, 233 bits, 239 bits, 283 bits, 409 bits and 571 bits
    - sectXXXr1 -> 163 bits, 193 bits, 233 bits, 283 bits, 409 bits and 571 bits
    - sectXXXr2 -> 163 bits and 193 bits
    - B_XXX -> 163 bits, 233 bits, 283 bits, 409 bits and 571 bits
    - brainpoolpXXXr1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits
    - brainpoolpXXXt1 -> 160 bits, 192 bits, 224 bits, 256 bits, 320 bits, 384 bits and 512 bits

### Key agreement with ECDH

```java
import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import java.security.KeyPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final KeyAgreementService keyAgreementService;

  @Autowired
  public MyComponent(KeyAgreementService keyAgreementService) {
    this.keyAgreementService = keyAgreementService;
  }

  public void generateSharedSecret(KeyPair ecdhKeyPairAlice, KeyPair ecdhKeyPairBob) {

    byte[] aliceSharedSecret =
        keyAgreementService.generateSecretKey(
            ecdhKeyPairAlice.getPrivate(), 
            ecdhKeyPairBob.getPublic());

    byte[] bobSharedSecret =
        keyAgreementService.generateSecretKey(
            ecdhKeyPairBob.getPrivate(), 
            ecdhKeyPairAlice.getPublic());

    // aliceSharedSecret == bobSharedSecret
  }
}
```
      
### Password based key derivation with PBKDF2 from string or byte array

```java
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final PBKDKeyService pbkdKeyService;

  @Autowired
  public MyComponent(@Qualifier("PBKDF2") PBKDKeyService pbkdKeyService) {
    this.pbkdKeyService = pbkdKeyService;
  }

  public void derivateSecretKeyFromStringPassword(String password, byte[] salt) {
    // Derivates a 256 bits length secret key
    SecretKey secretKey = pbkdKeyService.generateKey(password, salt, 256);
  }
  
  public void derivateSecretKeyFromByteArrayPassword(byte[] password, byte[] salt) {
    // Derivates a secret key from password
    SecretKey secretKey = pbkdKeyService.generateKey(password, salt, 256);
  }
}
```

To derivate a PBKDF2 key, the default `shaAlgorithm` algorithm used is `SHA512` and the default `iterations` is `131070`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  keyDerivationFunction:
    pbkdF2WithHmacSHA:
      shaAlgorithm: SHA512
      iterations: 65535
```

The supported `shaAlgorithm` algorithms to derivate a PBKDF2 key are,

      - SHA1
      - SHA256
      - SHA512
      - SHA3_256
      - SHA3_512
      
### Password based key derivation with Scrypt from string or byte array

```java
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final PBKDKeyService pbkdKeyService;

  @Autowired
  public MyComponent(@Qualifier("PBKDSCrypt") PBKDKeyService pbkdKeyService) {
    this.pbkdKeyService = pbkdKeyService;
  }

  public void derivateSecretKeyFromStringPassword(String password, byte[] salt) {
    // Derivates a 256 bits length secret key
    SecretKey secretKey = pbkdKeyService.generateKey(password, salt, 256);
  }

  public void derivateSecretKeyFromByteArrayPassword(byte[] password, byte[] salt) {
    // Derivates a secret key from password
    SecretKey secretKey = pbkdKeyService.generateKey(password, salt, 256);
  }
}
```

To derivate a Scrypt key, the default `cpuMemoryCost` used is `1048576`, the default `blockSize` used is `8` and the default `parallelization` used is `1`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  keyDerivationFunction:
    scrypt:
      cpuMemoryCost: 32768
      blockSize: 8
      parallelization: 2
```

### Password based key derivation with Argon2 from string or byte array

```java
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final PBKDKeyService pbkdKeyService;

  @Autowired
  public MyComponent(@Qualifier("PBKDArgon2") PBKDKeyService pbkdKeyService) {
    this.pbkdKeyService = pbkdKeyService;
  }

  public void derivateSecretKeyFromStringPassword(String password, byte[] salt) {
    // Derivates a 256 bits length secret key
    SecretKey secretKey = pbkdKeyService.generateKey(password, salt, 256);
  }

  public void derivateSecretKeyFromByteArrayPassword(byte[] password, byte[] salt) {
    // Derivates a secret key from password
    SecretKey secretKey = pbkdKeyService.generateKey(password, salt, 256);
  }
}
```

To derivate a Argon2 key, the default argon2's `type` used is `ARGON2_ID`, the default argon2's `version` used is `ARGON2_VERSION_13`, the default `iterations` are `3`, the default `memoryPowOfTwo` used is `18` and the default `parallelism` used is `4`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  keyDerivationFunction:
    argon2:
      type: ARGON2_ID
      version: ARGON2_VERSION_13
      iterations: 2
      memoryPowOfTwo: 18
      parallelism: 2
```

The supported argon2's `types` are,

    - ARGON2_D
    - ARGON2_I
    - ARGON2_ID
    
The supported argon2's `versions` are,

    - ARGON2_VERSION_10
    - ARGON2_VERSION_13

### Encrypt and decrypt byte array or stream with AES and ECB block mode of operation

```java
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVBasedCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SymmetricNonIVBasedCipherService aesCipherService;

  @Autowired
  public MyComponent(
      @Qualifier("AESNonIVBasedCipher") SymmetricNonIVBasedCipherService aesCipherService) {

    this.aesCipherService = aesCipherService;
  }

  /** Byte array **/

  public void encryptByteArray(SecretKey secretKey, byte[] clearContent) {
    byte[] encryptedContent = aesCipherService.encrypt(secretKey, clearContent);
  }

  public void decryptByteArray(SecretKey secretKey, byte[] encryptedContent) {
    byte[] clearContent = aesCipherService.decrypt(secretKey, encryptedContent);
  }

  /** Stream **/

  public void encryptStream(
      SecretKey secretKey,
      InputStream clearInputStream,
      OutputStream encryptedOutputStream) {

    // Input and output stream are flushed and closed before `encrypt` method returns
    aesCipherService.encrypt(secretKey, clearInputStream, encryptedOutputStream);
  }

  public void decryptStream(
      SecretKey secretKey,
      InputStream encryptedInputStream,
      OutputStream clearOutputStream) {

    // Input and output stream are flushed and closed before `decrypt` method returns
    aesCipherService.decrypt(secretKey, encryptedInputStream, clearOutputStream);
  }
}
```

### Encrypt and decrypt byte array or stream with AES and IV based block mode of operation

```java
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVBasedCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SymmetricIVBasedCipherService aesIVBasedCipherService;

  @Autowired
  public MyComponent(
      @Qualifier("AESIVBasedCipher") SymmetricIVBasedCipherService aesIVBasedCipherService) {

    this.aesIVBasedCipherService = aesIVBasedCipherService;
  }

  /** Byte array **/

  public void encryptByteArray(
      SecretKey secretKey,
      byte[] initializationVector,
      byte[] clearContent) {

    byte[] encryptedContent =
        aesIVBasedCipherService.encrypt(secretKey, initializationVector, clearContent);
  }

  public void decryptByteArray(
      SecretKey secretKey,
      byte[] initializationVector,
      byte[] encryptedContent) {

    byte[] clearContent =
        aesIVBasedCipherService.decrypt(secretKey, initializationVector, encryptedContent);
  }

  /** Stream **/

  public void encryptStream(
      SecretKey secretKey,
      byte[] initializationVector,
      InputStream clearInputStream,
      OutputStream encryptedOutputStream) {

    // Input and output stream are flushed and closed before `encrypt` method returns
    aesIVBasedCipherService.encrypt(
        secretKey,
        initializationVector,
        clearInputStream,
        encryptedOutputStream);
  }

  public void decryptStream(
      SecretKey secretKey,
      byte[] initializationVector,
      InputStream encryptedInputStream,
      OutputStream clearOutputStream) {

    // Input and output stream are flushed and closed before `decrypt` method returns
    aesIVBasedCipherService.decrypt(
        secretKey,
        initializationVector,
        encryptedInputStream,
        clearOutputStream);
  }
}
```

The default `blockMode` of operation used is `CRT`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  cipher:
    symmetric:
      aes:
        blockMode: CFB
```

Supported `blockMode` are,

    - CBC 
    - CFB 
    - OFB 
    - CTR

### Encrypt and decrypt with RSA

```java
import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherService;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final AsymmetricCipherService asymmetricKeyService;

  @Autowired
  public MyComponent(
      @Qualifier("RSACipher") AsymmetricCipherService asymmetricKeyService) {

    this.asymmetricKeyService = asymmetricKeyService;
  }

  public void encrypt(PublicKey publicKey, byte[] clearContent) {
    byte[] encryptedContent = asymmetricKeyService.encrypt(publicKey, clearContent);
  }

  public void decrypt(PrivateKey privateKey, byte[] encryptedContent) {
    byte[] clearContent = asymmetricKeyService.decrypt(privateKey, encryptedContent);
  }
}
```

The default `padding` used is `OAEPWithSHA256AndMGF1Padding`, but you can override this default value in the `application.yml`.  

```yaml
cryptography:
  cipher:
    asymmetric:
      rsa:
        padding: OAEPWithSHA1AndMGF1Padding
```

Supported `padding` modes are,

    - NoPadding
    - PKCS1Padding
    - OAEPWithMD5AndMGF1Padding
    - OAEPWithSHA1AndMGF1Padding
    - OAEPWithSHA224AndMGF1Padding
    - OAEPWithSHA256AndMGF1Padding
    - OAEPWithSHA384AndMGF1Padding
    - OAEPWithSHA512AndMGF1Padding
    - OAEPWithSHA3_224AndMGF1Padding
    - OAEPWithSHA3_256AndMGF1Padding
    - OAEPWithSHA3_384AndMGF1Padding
    - OAEPWithSHA3_512AndMGF1Padding
    - ISO9796_1Padding
    
### Generate and verify signature for a byte array or stream with RSA

```java
import com.theicenet.cryptography.signature.SignatureService;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SignatureService signatureService;

  @Autowired
  public MyComponent(@Qualifier("RSASignature") SignatureService signatureService) {
    this.signatureService = signatureService;
  }

  /** Byte array **/

  public void signByteArray(PrivateKey privateKey, byte[] content) {
    byte[] signature = signatureService.sign(privateKey, content);
  }

  public void verifyByteArray(PublicKey publicKey, byte[] content, byte[] signature) {
    boolean isValidSignature = signatureService.verify(publicKey, content, signature);
  }

  /** Stream **/

  public void signStream(PrivateKey privateKey, InputStream contentInputStream) {
    byte[] signature = signatureService.sign(privateKey, contentInputStream);
  }

  public void verifyStream(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    boolean isValidSignature = signatureService.verify(publicKey, contentInputStream, signature);
  }
}
```

The default `algorithm` used is `SHA256withRSA_PSS`, but you can override this default value in the `application.yml`.  

```yaml
cryptography:
  signature:
    asymmetric:
      rsa:
        algorithm: SHA1withRSA
```

Supported `algorithm` are,

    - NonewithRSA
    - RIPEMD128withRSA
    - RIPEMD160withRSA
    - RIPEMD256withRSA
    - SHA1withRSA
    - SHA224withRSA
    - SHA256withRSA
    - SHA384withRSA
    - SHA512withRSA
    - SHA3_224withRSA
    - SHA3_256withRSA
    - SHA3_384withRSA
    - SHA3_512withRSA
    - SHA1withRSAandMGF1
    - SHA256withRSAandMGF1
    - SHA384withRSAandMGF1
    - SHA512withRSAandMGF1
    - SHA1WithRSA_PSS
    - SHA224withRSA_PSS
    - SHA256withRSA_PSS
    - SHA384withRSA_PSS
    - SHA512withRSA_PSS

### Generate and verify signature for a byte array or stream with DSA

```java
import com.theicenet.cryptography.signature.SignatureService;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SignatureService signatureService;

  @Autowired
  public MyComponent(@Qualifier("DSASignature") SignatureService signatureService) {
    this.signatureService = signatureService;
  }

  /** Byte array **/

  public void signByteArray(PrivateKey privateKey, byte[] content) {
    byte[] signature = signatureService.sign(privateKey, content);
  }

  public void verifyByteArray(PublicKey publicKey, byte[] content, byte[] signature) {
    boolean isValidSignature = signatureService.verify(publicKey, content, signature);
  }

  /** Byte array **/

  public void signStream(PrivateKey privateKey, InputStream contentInputStream) {
    byte[] signature = signatureService.sign(privateKey, contentInputStream);
  }

  public void verifyStream(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    boolean isValidSignature = signatureService.verify(publicKey, contentInputStream, signature);
  }
}
```

The default `algorithm` used is `SHA256withDSA`, but you can override this default value in the `application.yml`.  

```yaml
cryptography:
  signature:
    asymmetric:
      dsa:
        algorithm: SHA1withDSA
```

Supported `algorithm` are,

    - NONEwithDSA
    - SHA1withDSA
    - SHA224withDSA
    - SHA256withDSA
    - SHA384withDSA
    - SHA512withDSA
    - SHA3_224withDSA
    - SHA3_256withDSA
    - SHA3_384withDSA
    - SHA3_512withDSA
    
### Generate and verify signature for a byte array or stream with ECDSA

```java
import com.theicenet.cryptography.signature.SignatureService;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SignatureService signatureService;

  @Autowired
  public MyComponent(@Qualifier("ECDSASignature") SignatureService signatureService) {
    this.signatureService = signatureService;
  }

  /** Byte array **/

  public void signByteArray(PrivateKey privateKey, byte[] content) {
    byte[] signature = signatureService.sign(privateKey, content);
  }

  public void verifyByteArray(PublicKey publicKey, byte[] content, byte[] signature) {
    boolean isValidSignature = signatureService.verify(publicKey, content, signature);
  }

  /** Stream **/

  public void signStream(PrivateKey privateKey, InputStream contentInputStream) {
    byte[] signature = signatureService.sign(privateKey, contentInputStream);
  }

  public void verifyStream(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    boolean isValidSignature = signatureService.verify(publicKey, contentInputStream, signature);
  }
}
```

The default `algorithm` used is `SHA256withECDSA`, but you can override this default value in the `application.yml`.  

```yaml
cryptography:
  signature:
    asymmetric:
      ecdsa:
        algorithm: SHA1withECDSA
```

Supported `algorithm` are,
    
    - NoneWithECDSA
    - RIPEMD160withECDSA
    - SHA1withECDSA
    - SHA224withECDSA
    - SHA256withECDSA
    - SHA384withECDSA
    - SHA512withECDSA
    - SHA3_224withECDSA
    - SHA3_256withECDSA
    - SHA3_384withECDSA
    - SHA3_512withECDSA

### Generate hash of byte array or stream

```java
import com.theicenet.cryptography.digest.DigestService;
import java.io.InputStream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final DigestService digestService;

  @Autowired
  public MyComponent(DigestService digestService) {
    this.digestService = digestService;
  }

  public void digestByteArray(byte[] content) {
    byte[] hash = digestService.digest(content);
  }

  public void digestStream(InputStream contentInputStream) {
    // Input stream is flushed and closed before `digest` method returns
    byte[] hash = digestService.digest(contentInputStream);
  }
}
```

The default `digest` algorithm used is `SHA_256`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  digest:
    algorithm: SHA-1
```

Supported `digest` algorithms are,

    - MD5
    - SHA_1
    - SHA_224
    - SHA_256
    - SHA_384
    - SHA_512
    - SHA3_224
    - SHA3_256
    - SHA3_384
    - SHA3_512
    - KECCAK_224
    - KECCAK_256
    - KECCAK_288
    - KECCAK_384
    - KECCAK_512
    - Whirlpool
    - Tiger
    - SM3

### MAC generation

```java
import com.theicenet.cryptography.mac.MacService;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final MacService macService;

  @Autowired
  public MyComponent(MacService macService) {
    this.macService = macService;
  }

  public void generateMAC(SecretKey secretKey, byte[] content) {
    byte[] hmac = macService.calculateMac(secretKey, content);
  }
}
```

The default `mac` algorithm used is `HmacSHA256`, but you can override this default value in the `application.yml`. 

```yaml
cryptography:
  mac:
    algorithm: HmacSHA1
```

Supported `mac` algorithms are,

    - HmacSHA1
    - HmacSHA224
    - HmacSHA256
    - HmacSHA384
    - HmacSHA512

### Generate random initialisation vector

```java
import com.theicenet.cryptography.randomise.RandomiseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final RandomiseService ivService;

  @Autowired
  public MyComponent(@Qualifier("IV") RandomiseService ivService) {
    this.ivService = ivService;
  }

  public void generateRandomInitializationVector() {
    // Generate 32 bytes random initialisation vector
    byte[] initializationVector = ivService.generateRandom(32);
  }
}
```

### Generate random salt

```java
import com.theicenet.cryptography.randomise.RandomiseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final RandomiseService saltService;

  @Autowired
  public MyComponent(@Qualifier("Salt") RandomiseService saltService) {
    this.saltService = saltService;
  }

  public void generateRandomSalt() {
    // Generate 128 bytes salt
    byte[] salt = saltService.generateRandom(128);
  }
}
```
