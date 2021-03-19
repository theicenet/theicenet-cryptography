# TheIceNet Cryptography library

TheIceNet Cryptography is a library which makes easy to develop cryptography-based, production-grade Spring Boot applications. 

The library homogenises how to use and invoke the similar families of cryptography primitives. TheIceNet Cryptography makes the consumer code agnostic from the underlying cryptography algorithm used, so it makes easy to switch the cryptography configuration or even the cryptography algorithm without affecting the consuming code.

TheIceNet Cryptography fully integrates with Spring Boot, making it easy and seamless to use cryptography in any Spring Boot based applications.  

Though TheIceNet Cryptography stands out in Spring Boot based applications, it can also be used in vanilla Java applications.
The main cryptographic modules `theicenet-cryptography-module` is 100% Spring agnostic, and so, this module can be easily be used in any non Spring based application.

## Table of contents

* TheIceNet Cryptography structure
    * [Modules](#modules)
* TheIceNet Cryptography supported algorithms
    * [Symmetric cryptography supported algorithms](#symmetric-cryptography-supported-algorithms)
    * [Asymmetric cryptography supported algorithms](#asymmetric-cryptography-supported-algorithms)
    * [Hashing supported algorithms](#hashing-supported-algorithms)
    * [Password Based Key Derivation (PBKD) supported algorithms](#password-based-key-derivation-supported-algorithms)
    * [Password Authenticated Key Exchange (PAKE) supported algorithms](#password-authenticated-key-exchange-supported-algorithms)
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
    * Password Authenticated Key Exchange (PAKE)
        * [Password authenticated key exchange with SRP6 version 6a](#password-authenticated-key-exchange-with-srp6-version-6a)
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
    * Secure random data generation 
        * [Generate secure random data](#generate-secure-random-data)
       
## Modules

There are four modules in TheIceNet Cryptography library, here is a quick overview of them:

* **theicenet-cryptography-spring-boot-starter** -> Spring Boot starter module which provides TheIceNet Cryptography library with full and seamless integration in any Spring Boot application.

* **theicenet-cryptography-module** -> Main cryptography module which provides with the foundations and cryptography components. TheIceNet Cryptography library can be enabled as well in vanilla Java application by just adding this module to your package manager. (The use of TheIceNet Cryptography library in vanilla Java applications is not included in this documentation) 
    
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

## Password Authenticated Key Exchange supported algorithms

TheIceNet Cryptography library can work with the next PAKE algorithms,

- **Augmented PAKE**
    - Secure Remote Password Protocol (SRP) version 6a (as described in the RFC 5054 specification)
 
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
      <version>1.1.1</version>
    </dependency>
```

In Gradle

```groovy
    compile group: 'com.theicenet', name: 'theicenet-cryptography-spring-boot-starter', version: '1.1.1'
```

## Building TheIceNet Cryptography library

TheIceNet Cryptography library uses Maven as building tool. To build the library follow the next steps,

-  Clone the repository
-  Change to the library root folder 
```shell
cd theicenet-cryptography
```
- Build the library
```shell
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

  private final AsymmetricKeyService ecdsaKeyService;

  @Autowired
  public MyComponent(@Qualifier("ECDSAKey_secpXXXk1") AsymmetricKeyService ecdsaKeyService) {
    this.ecdsaKeyService = ecdsaKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate key with 256 bits length
    KeyPair keyPair = ecdsaKeyService.generateKey(256);

    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}
```

The `curve` to be used must be set in the `application.yml`.

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdsa:
          curve: secpXXXk1
```

Multiple ECDSA key generators for different `curves` can be created in the same Spring Boot context.
Just specify the `curves` you wish to create ciphers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdsa:
          curve: 
            secpXXXk1,
            P_XXX,
            brainpoolpXXXr1
```

If only one single `curve` is specified in the `application.yml`, then the ECDSA key generator must be injected by,

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdsa:
          curve: secpXXXk1
```

```java
@Autowired
@Qualifier("ECDSAKey_secpXXXk1")
AsymmetricKeyService ecdsaKeyService;
```

The @Qualifier is required even if one single `curve` is specified.

If multiple `curves` are specified in the `application.yml`, then the key generator for each specific `curve` can be injected by,

```java
@Autowired
@Qualifier("ECDSAKey_${curve}")
AsymmetricKeyService ecdsaKeyService;
```

Where `${curve}` must be replaced by the `curve` to inject,

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdsa:
          curve:
            secpXXXk1,
            P_XXX,
            brainpoolpXXXr1
```

```java
@Autowired
@Qualifier("ECDSAKey_secpXXXk1")
AsymmetricKeyService ecdsaSecpXXXk1KeyService;

@Autowired
@Qualifier("ECDSAKey_P_XXX")
AsymmetricKeyService ecdsaPXXXKeyService;

@Autowired
@Qualifier("ECDSAKey_brainpoolpXXXr1")
AsymmetricKeyService ecdsaBrainpoolpXXXr1KeyService;
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

  private final AsymmetricKeyService ecdhKeyService;

  @Autowired
  public MyComponent(@Qualifier("ECDHKey_secpXXXk1") AsymmetricKeyService ecdhKeyService) {
    this.ecdhKeyService = ecdhKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate a key with 256 bits length
    KeyPair keyPair = ecdhKeyService.generateKey(256);

    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}
```

The `curve` to be used must be set in the `application.yml`.

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdh:
          curve: secpXXXk1
```

Multiple ECDH key generators for different `curves` can be created in the same Spring Boot context.
Just specify the `curves` you wish to create ciphers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdh:
          curve: 
            secpXXXk1,
            P_XXX,
            brainpoolpXXXr1
```

If only one single `curve` is specified in the `application.yml`, then the ECDH key generator must be injected by,

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdh:
          curve: secpXXXk1
```

```java
@Autowired
@Qualifier("ECDHKey_secpXXXk1")
AsymmetricKeyService ecdhKeyService;
```

The @Qualifier is required even if one single `curve` is specified.

If multiple `curves` are specified in the `application.yml`, then the key generator for each specific `curve` can be injected by,

```java
@Autowired
@Qualifier("ECDHKey_${curve}")
AsymmetricKeyService ecdhKeyService;
```

Where `${curve}` must be replaced by the `curve` to inject,

```yaml
cryptography:
  key:
    asymmetric:
      ecc:
        ecdh:
          curve:
            secpXXXk1,
            P_XXX,
            brainpoolpXXXr1
```

```java
@Autowired
@Qualifier("ECDHKey_secpXXXk1")
AsymmetricKeyService ecdhSecpXXXk1KeyService;

@Autowired
@Qualifier("ECDHKey_P_XXX")
AsymmetricKeyService ecdhPXXXKeyService;

@Autowired
@Qualifier("ECDHKey_brainpoolpXXXr1")
AsymmetricKeyService ecdhBrainpoolpXXXr1KeyService;
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

The configuration to derive a PBKDF2 key, can be set in the `application.yml`. 

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
The configuration to derive a Scrypt key, can be set in the `application.yml`.

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

The configuration to derive a Argon2 key, can be set in the `application.yml`.

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

### Password Authenticated Key Exchange with SRP6 version 6a

```java
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ClientValuesA;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ServerService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6ServerValuesB;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6VerifierService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SRP6VerifierService srp6VerifierService;
  private final SRP6ClientService srp6ClientService;
  private final SRP6ServerService srp6ServerService;
  private final SecureRandomDataService secureRandomDataService;

  @Autowired
  public MyComponent(
      @Qualifier("SRP6Verifier") SRP6VerifierService srp6VerifierService,
      @Qualifier("SRP6Client") SRP6ClientService srp6ClientService,
      @Qualifier("SRP6Server") SRP6ServerService srp6ServerService,
      @Qualifier("SecureRandomData") SecureRandomDataService secureRandomDataService) {

    this.srp6VerifierService = srp6VerifierService;
    this.srp6ClientService = srp6ClientService;
    this.srp6ServerService = srp6ServerService;
    this.secureRandomDataService = secureRandomDataService;
  }

  public void singsUpAndSignsInUsingSRP6(byte[] identity, byte[] password) {
    /********************* SIGN UP PROCESS ****************************/

    // Clients generates a salt
    final byte[] salt = secureRandomDataService.generateSecureRandomData(16);

    // Client produces the verifier.
    final byte[] signUpVerifier =
        srp6VerifierService.generateVerifier(salt, identity, password);

    // Client signs up into the server by sending (signUpVerifier, identity, salt) to the server
    // which stores (signUpVerifier, salt) indexed by identity


    /********************* SIGN IN PROCESS ****************************/

    // The client sends to the server identity which is attempting to sign in

    // The server fetches the verifier & salt (by identity) and generates the server's b and B values
    final SRP6ServerValuesB serverValuesB = srp6ServerService.computeValuesB(signUpVerifier);

    // The server sends to the client (serverValuesB#serverPublicValueB, salt)

    // Client generates the client's a and A values
    final SRP6ClientValuesA clientValuesA = srp6ClientService.computeValuesA();

    // The client generates the client's pre-master secret S
    final byte[] clientS =
        srp6ClientService.computeS(
            salt,
            identity,
            password,
            clientValuesA.getClientPrivateValueA(),
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPublicValueB());

    // Client generates client's M1
    final byte[] clientM1 =
        srp6ClientService.computeM1(
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPublicValueB(),
            clientS);

    // Client sends (clientValuesA#clientPublicValueA, M1) to the server

    // Server generates the server's pre-master secret S
    final byte[] serverS =
        srp6ServerService.computeS(
            signUpVerifier,
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPrivateValueB(),
            serverValuesB.getServerPublicValueB());

    // Server validates the received client's M1
    final boolean isClientM1Valid =
        srp6ServerService.isValidReceivedM1(
            clientValuesA.getClientPublicValueA(),
            serverValuesB.getServerPublicValueB(),
            serverS,
            clientM1);

    // If received client's M1 is invalid then the server will abort the singing in process at this point

    // If received client's M1 is valid then the server generates the server's M2
    final byte[] serverM2 =
        srp6ServerService.computeM2(
            clientValuesA.getClientPublicValueA(),
            serverS,
            clientM1);

    // The server sends the server's M2 to the client

    // Client validates the received server's M2
    final boolean isServerM2Valid =
        srp6ClientService.isValidReceivedM2(
            clientValuesA.getClientPublicValueA(),
            clientS,
            clientM1,
            serverM2);

    // If received server's M2 is invalid then client will abort the singing in process at this point

    // If received client's M1 and server's M2 are both valid, then the SRP6 authentication has been
    // successful and the client and server can generate the shared session key
    final byte[] clientSessionKey = srp6ClientService.computeSessionKey(clientS);
    final byte[] serverSessionKey = srp6ServerService.computeSessionKey(serverS);
  }
}
```

The `standard group (N,g)` and `hashing` algorithm to use for the SRP6 can be set in the `application.yml`.

```yaml
cryptography:
  pake:
    srp:
      v6a:
        standardGroup: SG_2048
        digest:
          algorithm: SHA_256
```

For SRP6 injection can be simplified to just,

```java
@Autowired
SRP6VerifierService srp6VerifierService;

@Autowired
SRP6ClientService srp6ClientService;

@Autowired
SRP6ServerService srp6ServerService;
```

The SRP6's supported `standard groups (N, g)` are,

    - SG_1024   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
    - SG_1536   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
    - SG_2048   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
    - SG_3072   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
    - SG_4096   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
    - SG_6144   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)
    - SG_8192   //Origin RFC 5054, appendix A (https://tools.ietf.org/html/rfc5054)

The SRP6's supported `hashing` algorithms are [any of the supported by the library](#hashing-supported-algorithms)

### Encrypt and decrypt byte array or stream with AES and ECB block mode of operation

```java
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SymmetricNonIVCipherService aesCipherService;

  @Autowired
  public MyComponent(
      @Qualifier("AESNonIVCipher_ECB") SymmetricNonIVCipherService aesCipherService) {
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

For AES with ECB block mode of operation, injection can be simplified to just,

```java
@Autowired
SymmetricNonIVCipherService aesCipherService;
```

### Encrypt and decrypt byte array or stream with AES and IV based block mode of operation

```java
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVCipherService;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SymmetricIVCipherService aesIVCipherService;

  @Autowired
  public MyComponent(
      @Qualifier("AESIVCipher_CFB") SymmetricIVCipherService aesIVCipherService) {
    this.aesIVCipherService = aesIVCipherService;
  }

  /** Byte array **/

  public void encryptByteArray(
      SecretKey secretKey,
      byte[] initializationVector,
      byte[] clearContent) {

    byte[] encryptedContent =
        aesIVCipherService.encrypt(secretKey, initializationVector, clearContent);
  }

  public void decryptByteArray(
      SecretKey secretKey,
      byte[] initializationVector,
      byte[] encryptedContent) {

    byte[] clearContent =
        aesIVCipherService.decrypt(secretKey, initializationVector, encryptedContent);
  }

  /** Stream **/

  public void encryptStream(
      SecretKey secretKey,
      byte[] initializationVector,
      InputStream clearInputStream,
      OutputStream encryptedOutputStream) {

    // Input and output stream are flushed and closed before `encrypt` method returns
    aesIVCipherService.encrypt(
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
    aesIVCipherService.decrypt(
        secretKey,
        initializationVector,
        encryptedInputStream,
        clearOutputStream);
  }
}
```

The `blockMode` of operation to be used must be set in the `application.yml`.

```yaml
cryptography:
  cipher:
    symmetric:
      aes:
        blockMode: CFB
```

Multiple AES ciphers for different `blockModes` of operation can be created in the same Spring Boot context.
Just specify the different `blockModes` of operation you wish to create ciphers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  cipher:
    symmetric:
      aes:
        blockMode: 
          CFB, 
          CRT, 
          CBC
```

If only one single `blockMode` of operation is specified in the `application.yml`, then the AES cipher can be just injected by,

```yaml
cryptography:
  cipher:
    symmetric:
      aes:
        blockMode: CFB
```

```java
@Autowired
SymmetricIVCipherService aesIVCipherService;
```

If multiple `blockModes` of operation are specified in the `application.yml`, then the cipher for each specific `blockMode` of operation can be injected by,

```java
@Autowired
@Qualifier("AESIVCipher_${blockMode}")
SymmetricIVCipherService aesIVCipherService;
```

Where `${blockMode}` must be replaced by the `blockMode` of operation to inject,

```yaml
cryptography:
  cipher:
    symmetric:
      aes:
        blockMode: 
          CFB, 
          CBC, 
          CTR
```

```java
@Autowired
@Qualifier("AESIVCipher_CFB")
SymmetricIVCipherService aesCFBIVCipherService;

@Autowired
@Qualifier("AESIVCipher_CBC")
SymmetricIVCipherService aesCFCIVCipherService;

@Autowired
@Qualifier("AESIVCipher_CTR")
SymmetricIVCipherService aesCTRIVCipherService;
```

Supported `blockModes` of operation are,

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
      @Qualifier("RSACipher_OAEPWithSHA1AndMGF1Padding") AsymmetricCipherService rsaCipherService) {

    this.asymmetricKeyService = rsaCipherService;
  }

  public void encrypt(PublicKey publicKey, byte[] clearContent) {
    byte[] encryptedContent = asymmetricKeyService.encrypt(publicKey, clearContent);
  }

  public void decrypt(PrivateKey privateKey, byte[] encryptedContent) {
    byte[] clearContent = asymmetricKeyService.decrypt(privateKey, encryptedContent);
  }
}
```

The `padding` to be used must be set in the `application.yml`.

```yaml
cryptography:
  cipher:
    asymmetric:
      rsa:
        padding: OAEPWithSHA1AndMGF1Padding
```

Multiple RSA ciphers for different `paddings` can be created in the same Spring Boot context.
Just specify the `paddings` you wish to create ciphers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  cipher:
    asymmetric:
      rsa:
        padding: 
          NoPadding, 
          OAEPWithSHA1AndMGF1Padding, 
          OAEPWithSHA256AndMGF1Padding
```

If only one single `padding` is specified in the `application.yml`, then the RSA cipher can be just injected by,

```yaml
cryptography:
  cipher:
    asymmetric:
      rsa:
        padding: OAEPWithSHA1AndMGF1Padding
```

```java
@Autowired
AsymmetricCipherService rsaCipherService;
```

If multiple `paddings` are specified in the `application.yml`, then the cipher for each specific `padding` can be injected by,

```java
@Autowired
@Qualifier("RSACipher_${padding}")
AsymmetricCipherService rsaCipherService;
```

Where `${padding}` must be replaced by the `padding` to inject,

```yaml
cryptography:
  cipher:
    asymmetric:
      rsa:
        padding: 
          NoPadding, 
          OAEPWithSHA1AndMGF1Padding, 
          OAEPWithSHA256AndMGF1Padding
```

```java
@Autowired
@Qualifier("RSACipher_NoPadding")
AsymmetricCipherService rsaNoPaddingCipherService;

@Autowired
@Qualifier("RSACipher_OAEPWithSHA1AndMGF1Padding")
AsymmetricCipherService rsaOAEPSHA1MGF1PaddingCipherService;

@Autowired
@Qualifier("RSACipher_OAEPWithSHA256AndMGF1Padding")
AsymmetricCipherService rsaOAEPSHA256MGF1PaddingaCipherService;
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

  private final SignatureService rsaSignatureService;

  @Autowired
  public MyComponent(@Qualifier("RSASignature_SHA1withRSA") SignatureService rsaSignatureService) {
    this.rsaSignatureService = rsaSignatureService;
  }

  /** Byte array **/

  public void signByteArray(PrivateKey privateKey, byte[] content) {
    byte[] signature = rsaSignatureService.sign(privateKey, content);
  }

  public void verifyByteArray(PublicKey publicKey, byte[] content, byte[] signature) {
    boolean isValidSignature = rsaSignatureService.verify(publicKey, content, signature);
  }

  /** Stream **/

  public void signStream(PrivateKey privateKey, InputStream contentInputStream) {
    byte[] signature = rsaSignatureService.sign(privateKey, contentInputStream);
  }

  public void verifyStream(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    boolean isValidSignature = rsaSignatureService.verify(publicKey, contentInputStream, signature);
  }
}
```

The `algorithm` to be used must be set in the `application.yml`.

```yaml
cryptography:
  signature:
    asymmetric:
      rsa:
        algorithm: SHA1withRSA
```

Multiple RSA signers for different `algorithms` can be created in the same Spring Boot context.
Just specify the `algorithms` you wish to create signers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  signature:
    asymmetric:
      rsa:
        algorithm: 
          SHA1withRSA,
          SHA256withRSA,
          RIPEMD256withRSA
```

If only one single `algorithm` is specified in the `application.yml`, then the RSA signer must injected by,

```yaml
cryptography:
  signature:
    asymmetric:
      rsa:
        algorithm: SHA1withRSA
```

```java
@Autowired
@Qualifier("RSASignature_SHA1withRSA")
SignatureService rsaSignatureService;
```

The @Qualifier is required even if one single `algorithm` is specified.

If multiple `algorithms` are specified in the `application.yml`, then the signer for each specific `algorithm` can be injected by,

```java
@Autowired
@Qualifier("RSASignature_${algorithm}")
SignatureService rsaSignatureService;
```

Where `${algorithm}` must be replaced by the `algorithm` to inject,

```yaml
cryptography:
  signature:
    asymmetric:
      rsa:
        algorithm:
          SHA1withRSA,
          SHA256withRSA,
          RIPEMD256withRSA
```

```java
@Autowired
@Qualifier("RSASignature_SHA1withRSA")
SignatureService rsaSHA1SignatureService;

@Autowired
@Qualifier("RSASignature_SHA256withRSA")
SignatureService rsaSHA256SignatureService;

@Autowired
@Qualifier("RSASignature_RIPEMD256withRSA")
SignatureService rsaRIPEMD256SignatureService;
```

Supported `algorithms` are,

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

  private final SignatureService dsaSignatureService;

  @Autowired
  public MyComponent(@Qualifier("DSASignature_SHA1withDSA") SignatureService dsaSignatureService) {
    this.dsaSignatureService = dsaSignatureService;
  }

  /** Byte array **/

  public void signByteArray(PrivateKey privateKey, byte[] content) {
    byte[] signature = dsaSignatureService.sign(privateKey, content);
  }

  public void verifyByteArray(PublicKey publicKey, byte[] content, byte[] signature) {
    boolean isValidSignature = dsaSignatureService.verify(publicKey, content, signature);
  }

  /** Byte array **/

  public void signStream(PrivateKey privateKey, InputStream contentInputStream) {
    byte[] signature = dsaSignatureService.sign(privateKey, contentInputStream);
  }

  public void verifyStream(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    boolean isValidSignature = dsaSignatureService.verify(publicKey, contentInputStream, signature);
  }
}
```

The `algorithm` to be used must be set in the `application.yml`.

```yaml
cryptography:
  signature:
    asymmetric:
      dsa:
        algorithm: SHA1withDSA
```

Multiple DSA signers for different `algorithms` can be created in the same Spring Boot context.
Just specify the `algorithms` you wish to create signers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  signature:
    asymmetric:
      dsa:
        algorithm:
          SHA1withDSA,
          SHA256withDSA,
          SHA512withDSA
```

If only one single `algorithm` is specified in the `application.yml`, then the DSA signer must be injected by,

```yaml
cryptography:
  signature:
    asymmetric:
      dsa:
        algorithm: SHA1withDSA
```

```java
@Autowired
@Qualifier("DSASignature_SHA1withDSA")
SignatureService dsaSignatureService;
```

The @Qualifier is required even if one single `algorithm` is specified.

If multiple `algorithms` are specified in the `application.yml`, then the signer for each specific `algorithm` can be injected by,

```java
@Autowired
@Qualifier("DSASignature_${algorithm}")
SignatureService dsaSignatureService;
```

Where `${algorithm}` must be replaced by the `algorithm` to inject,

```yaml
cryptography:
  signature:
    asymmetric:
      dsa:
        algorithm:
          SHA1withDSA,
          SHA256withDSA,
          SHA512withDSA
```

```java
@Autowired
@Qualifier("DSASignature_SHA1withDSA")
SignatureService dsaSHA1SignatureService;

@Autowired
@Qualifier("DSASignature_SHA256withDSA")
SignatureService dsaSHA256SignatureService;

@Autowired
@Qualifier("DSASignature_SHA512withDSA")
SignatureService dsaSHA512SignatureService;
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

  private final SignatureService ecdsaSignatureService;

  @Autowired
  public MyComponent(
      @Qualifier("ECDSASignature_SHA1withECDSA") SignatureService ecdsaSignatureService) {
    this.ecdsaSignatureService = ecdsaSignatureService;
  }

  /** Byte array **/

  public void signByteArray(PrivateKey privateKey, byte[] content) {
    byte[] signature = ecdsaSignatureService.sign(privateKey, content);
  }

  public void verifyByteArray(PublicKey publicKey, byte[] content, byte[] signature) {
    boolean isValidSignature = ecdsaSignatureService.verify(publicKey, content, signature);
  }

  /** Stream **/

  public void signStream(PrivateKey privateKey, InputStream contentInputStream) {
    byte[] signature = ecdsaSignatureService.sign(privateKey, contentInputStream);
  }

  public void verifyStream(PublicKey publicKey, InputStream contentInputStream, byte[] signature) {
    boolean isValidSignature = ecdsaSignatureService.verify(publicKey, contentInputStream, signature);
  }
}
```

The `algorithm` to be used must be set in the `application.yml`.

```yaml
cryptography:
  signature:
    asymmetric:
      ecdsa:
        algorithm: SHA1withECDSA
```

Multiple ECDSA signers for different `algorithms` can be created in the same Spring Boot context.
Just specify the `algorithms` you wish to create signers for into the Spring Context, separated by a comma,

```yaml
cryptography:
  signature:
    asymmetric:
      ecdsa:
        algorithm: 
          SHA1withECDSA,
          SHA256withECDSA,
          SHA512withECDSA
```

If only one single `algorithm` is specified in the `application.yml`, then the ECDSA signer must be injected by,

```yaml
cryptography:
  signature:
    asymmetric:
      ecdsa:
        algorithm: SHA1withECDSA
```

```java
@Autowired
@Qualifier("ECDSASignature_SHA1withECDSA")
SignatureService ecdsaSignatureService;
```

The @Qualifier is required even if one single `algorithm` is specified.

If multiple `algorithms` are specified in the `application.yml`, then the signer for each specific `algorithm` can be injected by,

```java
@Autowired
@Qualifier("ECDSASignature_${algorithm}")
SignatureService ecdsaSignatureService;
```

Where `${algorithm}` must be replaced by the `algorithm` to inject,

```yaml
cryptography:
  signature:
    asymmetric:
      ecdsa:
        algorithm:
          SHA1withECDSA,
          SHA256withECDSA,
          SHA512withECDSA
```

```java
@Autowired
@Qualifier("ECDSASignature_SHA1withDSA")
SignatureService ecdsaSHA1SignatureService;

@Autowired
@Qualifier("ECDSASignature_SHA256withDSA")
SignatureService ecdsaSHA256SignatureService;

@Autowired
@Qualifier("ECDSASignature_SHA512withDSA")
SignatureService ecdsaSHA512SignatureService;
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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final DigestService digestService;

  @Autowired
  public MyComponent(
      @Qualifier("Digest_SHA_1") DigestService digestService) {
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

The `digest algorithm` to be used must be set in the `application.yml`.

```yaml
cryptography:
  digest:
    algorithm: SHA_1
```

Multiple digesters for different `digest algorithms` can be created in the same Spring Boot context.
Just specify the `digest algorithms` you wish to create a digester for into the Spring Context, separated by a comma,

```yaml
cryptography:
  digest:
    algorithm:
      SHA_1,
      SHA_256,
      SHA_512
```

If only one single `digest algorithm` is specified in the `application.yml`, then the digester can be just injected by,

```yaml
cryptography:
  digest:
    algorithm: SHA_1
```

```java
@Autowired
DigestService digestService;
```

If multiple `digest algorithms` are specified in the `application.yml`, then the digester for each specific `digest algorithm` can be injected by,

```java
@Autowired
@Qualifier("Digest_${algorithm}")
DigestService digestService;
```

Where `${algorithm}` must be replaced by the `digest algorithm` to inject,

```yaml
cryptography:
  digest:
    algorithm:
      SHA_1,
      SHA_256,
      SHA_512
```

```java
@Autowired
@Qualifier("Digest_SHA_1")
DigestService sha1DigestService;

@Autowired
@Qualifier("Digest_SHA_256")
DigestService sha256DigestService;

@Autowired
@Qualifier("Digest_SHA_512")
DigestService sha512DigestService;
```

Supported `digest algorithms` are,

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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final MacService macService;

  @Autowired
  public MyComponent(
      @Qualifier("MAC_HmacSHA1") MacService macService) {
    this.macService = macService;
  }

  public void generateMAC(SecretKey secretKey, byte[] content) {
    byte[] hmac = macService.calculateMac(secretKey, content);
  }
}
```

The `algorithm` to be used must be set in the `application.yml`.

```yaml
cryptography:
  mac:
    algorithm: HmacSHA1
```

Multiple MAC calculators for different `algorithms` can be created in the same Spring Boot context.
Just specify the `algorithms` you wish to create a calculator for into the Spring Context, separated by a comma,
RFC5054SRP6ServerService
```yaml
cryptography:
  mac:
    algorithm: 
      HmacSHA1,
      HmacSHA256,
      HmacSHA512
```

If only one single `algorithm` is specified in the `application.yml`, then the MAC calculator can be just injected by,

```yaml
cryptography:
  mac:
    algorithm: HmacSHA1
```

```java
@Autowired
MacService macService;
```

If multiple `algorithms` are specified in the `application.yml`, then the calculator for each specific `algorithm` can be injected by,

```java
@Autowired
@Qualifier("MAC_${algorithm}") 
MacService macService;
```

Where `${algorithm}` must be replaced by the MAC `algorithm` to inject,

```yaml
cryptography:
  mac:
    algorithm:
      HmacSHA1,
      HmacSHA256,
      HmacSHA512
```

```java
@Autowired
@Qualifier("MAC_HmacSHA1") 
MacService sha1Service;

@Autowired
@Qualifier("MAC_HmacSHA256") 
MacService sha256Service;

@Autowired
@Qualifier("MAC_HmacSHA512") 
MacService sha512Service;
```

Supported MAC `algorithms` are,

    - HmacSHA1
    - HmacSHA224
    - HmacSHA256
    - HmacSHA384
    - HmacSHA512

### Generate secure random data

```java
import com.theicenet.cryptography.random.SecureRandomDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final SecureRandomDataService secureRandomDataService;

  @Autowired
  public MyComponent(
      @Qualifier("SecureRandomData") SecureRandomDataService secureRandomDataService) {
    this.secureRandomDataService = secureRandomDataService;
  }

  public void generateRandomData() {
    // Generate 32 bytes random data
    byte[] secureRandomData = secureRandomDataService.generateSecureRandomData(32);
  }
}
```

The secure random data service can be just injected by,

```java
@Autowired
SecureRandomDataService secureRandomDataService;
```