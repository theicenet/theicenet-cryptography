/*
 * Copyright 2019-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.theicenet.cryptography;

import com.theicenet.cryptography.cipher.asymmetric.AsymmetricCipherService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.JCARSACipherService;
import com.theicenet.cryptography.cipher.asymmetric.rsa.RSAPadding;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherIVBasedModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVBasedModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricIVBasedCipherService;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVBasedCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESIVBasedCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESNonIVBasedCipherService;
import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.dsa.JCADSAKeyService;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCCurve;
import com.theicenet.cryptography.key.asymmetric.ecc.ecdh.JCAECDHKeyService;
import com.theicenet.cryptography.key.asymmetric.ecc.ecdsa.JCAECDSAKeyService;
import com.theicenet.cryptography.key.asymmetric.rsa.JCARSAKeyService;
import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import com.theicenet.cryptography.key.symmetric.aes.JCAAESKeyService;
import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import com.theicenet.cryptography.keyagreement.ecc.ecdh.JCACEDHKeyAgreementService;
import com.theicenet.cryptography.mac.MacService;
import com.theicenet.cryptography.mac.hmac.HmacAlgorithm;
import com.theicenet.cryptography.mac.hmac.JCAHmacService;
import com.theicenet.cryptography.pbkd.PBKDKeyService;
import com.theicenet.cryptography.pbkd.argon2.Argon2Configuration;
import com.theicenet.cryptography.pbkd.argon2.Argon2Type;
import com.theicenet.cryptography.pbkd.argon2.Argon2Version;
import com.theicenet.cryptography.pbkd.argon2.PBKDArgon2KeyService;
import com.theicenet.cryptography.pbkd.pbkdf2.JCAPBKDF2WithHmacSHAKeyService;
import com.theicenet.cryptography.pbkd.pbkdf2.PBKDF2Configuration;
import com.theicenet.cryptography.pbkd.pbkdf2.PBKDF2ShaAlgorithm;
import com.theicenet.cryptography.pbkd.scrypt.PBKDSCryptKeyService;
import com.theicenet.cryptography.pbkd.scrypt.SCryptConfiguration;
import com.theicenet.cryptography.random.SecureRandomDataService;
import com.theicenet.cryptography.random.JCASecureRandomDataService;
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

/**
 * @author Juan Fidalgo
 */
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

    return new JCAAESIVBasedCipherService(blockMode);
  }

  @Bean("AESNonIVBasedCipher")
  public SymmetricNonIVBasedCipherService aesCipherService() {
    return new JCAAESNonIVBasedCipherService(BlockCipherNonIVBasedModeOfOperation.ECB);
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
      @Value("${cryptography.key.asymmetric.ecc.ecdsa.curve:brainpoolpXXXt1}") ECCCurve curve,
      SecureRandom secureRandom) {

    return new JCAECDSAKeyService(curve, secureRandom);
  }

  @Bean("ECDSASignature")
  public SignatureService ecdsaSignatureService(
      @Value("${cryptography.signature.asymmetric.ecdsa.algorithm:SHA256withECDSA}") ECDSASignatureAlgorithm algorithm) {

    return new JCAECDSASignatureService(algorithm);
  }

  @Bean("ECDHKey")
  public AsymmetricKeyService ecdhKeyService(
      @Value("${cryptography.key.asymmetric.ecc.ecdh.curve:brainpoolpXXXt1}") ECCCurve curve,
      SecureRandom secureRandom) {

    return new JCAECDHKeyService(curve, secureRandom);
  }

  @Bean("ECDHKeyAgreement")
  public KeyAgreementService ecdhKeyAgreementService() {
    return new JCACEDHKeyAgreementService();
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
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.shaAlgorithm:SHA512}") PBKDF2ShaAlgorithm shaAlgorithm,
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

  @Bean("SecureRandom")
  public SecureRandomDataService secureRandom(SecureRandom secureRandom) {
    return new JCASecureRandomDataService(secureRandom);
  }

  @Bean("Digest")
  public DigestService digestService(
      @Value("${cryptography.digest.algorithm:SHA_256}") DigestAlgorithm algorithm) {

    return new JCADigestService(algorithm);
  }

  @Bean("Hmac")
  public MacService hmacService(
      @Value("${cryptography.mac.algorithm:HmacSHA256}") HmacAlgorithm algorithm) {

    return new JCAHmacService(algorithm);
  }
}
