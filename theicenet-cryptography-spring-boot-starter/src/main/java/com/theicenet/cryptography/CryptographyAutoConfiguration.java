package com.theicenet.cryptography;

import com.theicenet.cryptography.signature.asymmetric.dsa.DSASignatureAlgorithm;
import com.theicenet.cryptography.signature.asymmetric.dsa.DSASignatureService;
import com.theicenet.cryptography.signature.asymmetric.dsa.JCADSASignatureService;
import com.theicenet.cryptography.key.asymmetric.dsa.DSAKeyService;
import com.theicenet.cryptography.key.asymmetric.dsa.JCADSAKeyService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.JCARSACryptographyService;
import com.theicenet.cryptography.signature.asymmetric.rsa.JCARSASignatureService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.RSACryptographyService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.RSAPadding;
import com.theicenet.cryptography.signature.asymmetric.rsa.RSASignatureAlgorithm;
import com.theicenet.cryptography.signature.asymmetric.rsa.RSASignatureService;
import com.theicenet.cryptography.key.asymmetric.rsa.JCARSAKeyService;
import com.theicenet.cryptography.key.asymmetric.rsa.RSAKeyService;
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.pbkd.argon2.Argon2Configuration;
import com.theicenet.cryptography.pbkd.argon2.Argon2Type;
import com.theicenet.cryptography.pbkd.argon2.Argon2Version;
import com.theicenet.cryptography.pbkd.argon2.PBKDArgon2Service;
import com.theicenet.cryptography.pbkd.pbkdf2.JCAPBKDF2WithHmacSHAKeyService;
import com.theicenet.cryptography.pbkd.pbkdf2.PBKDF2Configuration;
import com.theicenet.cryptography.pbkd.pbkdf2.ShaAlgorithm;
import com.theicenet.cryptography.pbkd.scrypt.PBKDSCryptService;
import com.theicenet.cryptography.pbkd.scrypt.SCryptConfiguration;
import com.theicenet.cryptography.pbkd.salt.JCASaltService;
import com.theicenet.cryptography.pbkd.salt.SaltService;
import com.theicenet.cryptography.cipher.symmetric.aes.AESCryptographyService;
import com.theicenet.cryptography.cipher.symmetric.aes.BlockCipherModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESCryptographyService;
import com.theicenet.cryptography.cipher.symmetric.aes.iv.IVService;
import com.theicenet.cryptography.cipher.symmetric.aes.iv.JCAIVService;
import com.theicenet.cryptography.key.symmetric.aes.AESKeyService;
import com.theicenet.cryptography.key.symmetric.aes.JCAAESKeyService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;

@Configuration
public class CryptographyAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }

  @Bean
  public AESCryptographyService aesCryptographyService(
      @Value("${cryptography.symmetric.aes.blockMode:CTR}") BlockCipherModeOfOperation blockMode) {

    return new JCAAESCryptographyService(blockMode);
  }

  @Bean
  public AESKeyService aesKeyService(SecureRandom secureRandom) {
    return new JCAAESKeyService(secureRandom);
  }

  @Bean
  public IVService ivService(SecureRandom secureRandom) {
    return new JCAIVService(secureRandom);
  }

  @Bean
  public RSAKeyService rsaKeyService(SecureRandom secureRandom) {
    return new JCARSAKeyService(secureRandom);
  }

  @Bean
  public RSACryptographyService rsaCryptographyService(
      @Value("${cryptography.asymmetric.rsa.padding:OAEPWithSHA256AndMGF1Padding}") RSAPadding padding) {

    return new JCARSACryptographyService(padding);
  }

  @Bean
  public RSASignatureService rsaSignatureService(
      @Value("${signature.asymmetric.rsa.algorithm:SHA256withRSA_PSS}") RSASignatureAlgorithm algorithm) {

    return new JCARSASignatureService(algorithm);
  }

  @Bean
  public DSAKeyService dsaKeyService(SecureRandom secureRandom) {
    return new JCADSAKeyService(secureRandom);
  }

  @Bean
  public DSASignatureService dsaSignatureService(
      @Value("${signature.asymmetric.dsa.algorithm:SHA256withDSA}") DSASignatureAlgorithm algorithm) {

    return new JCADSASignatureService(algorithm);
  }

  @Bean("PBKDArgon2")
  public PBKDKeyService pbkdKeyArgon2Service(
      @Value("${keyDerivationFunction.argon2.type:ARGON2_ID}") Argon2Type type,
      @Value("${keyDerivationFunction.argon2.version:ARGON2_VERSION_13}") Argon2Version version,
      @Value("${keyDerivationFunction.argon2.iterations:3}") Integer iterations,
      @Value("${keyDerivationFunction.argon2.memoryPowOfTwo:18}") Integer memoryPowOfTwo,
      @Value("${keyDerivationFunction.argon2.parallelism:4}") Integer parallelism) {

    return new PBKDArgon2Service(
        new Argon2Configuration(type, version, iterations, memoryPowOfTwo, parallelism));
  }

  @Bean("PBKDF2")
  public PBKDKeyService pbkdKeyPBKDF2Service(
      @Value("${keyDerivationFunction.pbkdF2WithHmacSHA.shaAlgorithm:SHA512}") ShaAlgorithm shaAlgorithm,
      @Value("${keyDerivationFunction.pbkdF2WithHmacSHA.iterations:131070}") Integer iterations) {

    return new JCAPBKDF2WithHmacSHAKeyService(new PBKDF2Configuration(shaAlgorithm, iterations));
  }

  @Bean("PBKDSCrypt")
  public PBKDKeyService pbkdKeySCryptService(
      @Value("${keyDerivationFunction.scrypt.cpuMemoryCost:1048576}") Integer cpuMemoryCost,
      @Value("${keyDerivationFunction.scrypt.blockSize:8}") Integer blockSize,
      @Value("${keyDerivationFunction.scrypt.parallelization:1}") Integer parallelization) {

    return new PBKDSCryptService(
        new SCryptConfiguration(cpuMemoryCost, blockSize, parallelization));
  }

  @Bean
  public SaltService saltService(SecureRandom secureRandom) {
    return new JCASaltService(secureRandom);
  }
}
