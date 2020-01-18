package com.theicenet.cryptography;

import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.JCARSACipherService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.RSAPadding;
import com.theicenet.cryptography.cipher.symmetric.SymmetricCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVBasedCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.BlockCipherIVBasedModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESECBCipherService;
import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.key.asymmetric.ecdsa.ECDSACurve;
import com.theicenet.cryptography.key.asymmetric.ecdsa.JCAECDSAKeyService;
import com.theicenet.cryptography.randomise.RandomiseService;
import com.theicenet.cryptography.randomise.iv.JCAIVService;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.dsa.JCADSAKeyService;
import com.theicenet.cryptography.key.asymmetric.rsa.JCARSAKeyService;
import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import com.theicenet.cryptography.key.symmetric.aes.JCAAESKeyService;
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.pbkd.argon2.Argon2Configuration;
import com.theicenet.cryptography.pbkd.argon2.Argon2Type;
import com.theicenet.cryptography.pbkd.argon2.Argon2Version;
import com.theicenet.cryptography.pbkd.argon2.PBKDArgon2KeyService;
import com.theicenet.cryptography.pbkd.pbkdf2.JCAPBKDF2WithHmacSHAKeyService;
import com.theicenet.cryptography.pbkd.pbkdf2.PBKDF2Configuration;
import com.theicenet.cryptography.pbkd.pbkdf2.ShaAlgorithm;
import com.theicenet.cryptography.randomise.salt.JCASaltService;
import com.theicenet.cryptography.pbkd.scrypt.PBKDSCryptKeyService;
import com.theicenet.cryptography.pbkd.scrypt.SCryptConfiguration;
import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.signature.dsa.DSASignatureAlgorithm;
import com.theicenet.cryptography.signature.dsa.JCADSASignatureService;
import com.theicenet.cryptography.signature.ecdsa.ECDSASignatureAlgorithm;
import com.theicenet.cryptography.signature.ecdsa.JCAECDSASignatureService;
import com.theicenet.cryptography.signature.rsa.JCARSASignatureService;
import com.theicenet.cryptography.signature.rsa.RSASignatureAlgorithm;
import java.security.SecureRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptographyAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }

  @Bean("AESKey")
  public SymmetricKeyService aesKeyService(SecureRandom secureRandom) {
    return new JCAAESKeyService(secureRandom);
  }

  @Bean("AESIVBasedCipher")
  public SymmetricIVBasedCipherService aesIVBasedCipherService(
      @Value("${cryptography.cipher.symmetric.aes.blockMode:CTR}") BlockCipherIVBasedModeOfOperation blockMode) {

    return new JCAAESCipherService(blockMode);
  }

  @Bean("AESCipher")
  public SymmetricCipherService aesCipherService() {
    return new JCAAESECBCipherService();
  }

  @Bean("RSAKey")
  public AsymmetricKeyService rsaKeyService(SecureRandom secureRandom) {
    return new JCARSAKeyService(secureRandom);
  }

  @Bean("RSACipher")
  public AsymmetricCipherService rsaCipherService(
      @Value("${cryptography.cipher.asymmetric.rsa.padding:OAEPWithSHA256AndMGF1Padding}") RSAPadding padding) {

    return new JCARSACipherService(padding);
  }

  @Bean("RSASignature")
  public SignatureService rsaSignatureService(
      @Value("${cryptography.signature.asymmetric.rsa.algorithm:SHA256withRSA_PSS}") RSASignatureAlgorithm algorithm) {

    return new JCARSASignatureService(algorithm);
  }

  @Bean("DSAKey")
  public AsymmetricKeyService dsaKeyService(SecureRandom secureRandom) {
    return new JCADSAKeyService(secureRandom);
  }

  @Bean("DSASignature")
  public SignatureService dsaSignatureService(
      @Value("${cryptography.signature.asymmetric.dsa.algorithm:SHA256withDSA}") DSASignatureAlgorithm algorithm) {

    return new JCADSASignatureService(algorithm);
  }

  @Bean("ECDSAKey")
  public AsymmetricKeyService ecdsaKeyService(
      @Value("${cryptography.key.ecdsa.curve:brainpoolpXXXt1}") ECDSACurve curve,
      SecureRandom secureRandom) {

    return new JCAECDSAKeyService(curve, secureRandom);
  }

  @Bean("ECDSASignature")
  public SignatureService ecdsaSignatureService(
      @Value("${cryptography.signature.asymmetric.ecdsa.algorithm:SHA256withECDSA}") ECDSASignatureAlgorithm algorithm) {

    return new JCAECDSASignatureService(algorithm);
  }


  @Bean("PBKDArgon2")
  public PBKDKeyService pbkdArgon2KeyService(
      @Value("${cryptography.keyDerivationFunction.argon2.type:ARGON2_ID}") Argon2Type type,
      @Value("${cryptography.keyDerivationFunction.argon2.version:ARGON2_VERSION_13}") Argon2Version version,
      @Value("${cryptography.keyDerivationFunction.argon2.iterations:3}") Integer iterations,
      @Value("${cryptography.keyDerivationFunction.argon2.memoryPowOfTwo:18}") Integer memoryPowOfTwo,
      @Value("${cryptography.keyDerivationFunction.argon2.parallelism:4}") Integer parallelism) {

    return new PBKDArgon2KeyService(
        new Argon2Configuration(type, version, iterations, memoryPowOfTwo, parallelism));
  }

  @Bean("PBKDF2")
  public PBKDKeyService pbkdF2KeyService(
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.shaAlgorithm:SHA512}") ShaAlgorithm shaAlgorithm,
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.iterations:131070}") Integer iterations) {

    return new JCAPBKDF2WithHmacSHAKeyService(new PBKDF2Configuration(shaAlgorithm, iterations));
  }

  @Bean("PBKDSCrypt")
  public PBKDKeyService pbkdSCryptKeyService(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost:1048576}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize:8}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization:1}") Integer parallelization) {

    return new PBKDSCryptKeyService(
        new SCryptConfiguration(cpuMemoryCost, blockSize, parallelization));
  }

  @Bean("IV")
  public RandomiseService ivService(SecureRandom secureRandom) {
    return new JCAIVService(secureRandom);
  }

  @Bean("Salt")
  public RandomiseService saltService(SecureRandom secureRandom) {
    return new JCASaltService(secureRandom);
  }

  @Bean("Digest")
  public DigestService digestService(
      @Value("${cryptography.digest.algorithm:SHA-256}") DigestAlgorithm algorithm) {

    return new JCADigestService(algorithm);
  }
}
