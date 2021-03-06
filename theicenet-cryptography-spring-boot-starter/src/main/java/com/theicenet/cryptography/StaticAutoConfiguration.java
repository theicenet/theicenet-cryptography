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

import com.theicenet.cryptography.cipher.symmetric.BlockCipherNonIVModeOfOperation;
import com.theicenet.cryptography.cipher.symmetric.SymmetricNonIVCipherService;
import com.theicenet.cryptography.cipher.symmetric.aes.JCAAESNonIVCipherService;
import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.digest.DigestService;
import com.theicenet.cryptography.digest.JCADigestService;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.dsa.JCADSAKeyService;
import com.theicenet.cryptography.key.asymmetric.ecc.ECCCurve;
import com.theicenet.cryptography.key.asymmetric.ecc.ecdh.JCAECDHKeyService;
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
import com.theicenet.cryptography.random.JCASecureRandomDataService;
import com.theicenet.cryptography.random.SecureRandomDataService;
import com.theicenet.cryptography.signature.SignatureService;
import com.theicenet.cryptography.signature.ecdsa.ECDSASignatureAlgorithm;
import com.theicenet.cryptography.signature.ecdsa.JCAECDSASignatureService;
import java.security.SecureRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

/**
 * IMPORTANT:
 *  Please note that SecureRandom bean is defined in SecureRandomDynamicContextInitializer
 *  as it's required in some other Context initializers, which are run earlier than this Auto
 *  Configuration. Please ignore any IDE warning on this matter.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
@Configuration
public class StaticAutoConfiguration {

  @Lazy
  @Bean("AESKey")
  public SymmetricKeyService aesKeyService(SecureRandom secureRandom) {
    return new JCAAESKeyService(secureRandom);
  }

  @Lazy
  @Bean("AESNonIVCipher_ECB")
  public SymmetricNonIVCipherService aesCipherService() {
    return new JCAAESNonIVCipherService(BlockCipherNonIVModeOfOperation.ECB);
  }

  @Lazy
  @Bean("RSAKey")
  public AsymmetricKeyService rsaKeyService(SecureRandom secureRandom) {
    return new JCARSAKeyService(secureRandom);
  }

  @Lazy
  @Bean("DSAKey")
  public AsymmetricKeyService dsaKeyService(SecureRandom secureRandom) {
    return new JCADSAKeyService(secureRandom);
  }

  @Lazy
  @Bean("ECDSASignature")
  public SignatureService ecdsaSignatureService(
      @Value("${cryptography.signature.asymmetric.ecdsa.algorithm:SHA256withECDSA}") ECDSASignatureAlgorithm algorithm) {

    return new JCAECDSASignatureService(algorithm);
  }

  @Lazy
  @Bean("ECDHKeyAgreement")
  public KeyAgreementService ecdhKeyAgreementService() {
    return new JCACEDHKeyAgreementService();
  }

  @Lazy
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

  @Lazy
  @Bean("PBKDF2")
  public PBKDKeyService pbkdF2KeyService(
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.shaAlgorithm:SHA512}") PBKDF2ShaAlgorithm shaAlgorithm,
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.iterations:131070}") Integer iterations) {

    return new JCAPBKDF2WithHmacSHAKeyService(new PBKDF2Configuration(shaAlgorithm, iterations));
  }

  @Lazy
  @Bean("PBKDSCrypt")
  public PBKDKeyService pbkdSCryptKeyService(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost:1048576}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize:8}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization:1}") Integer parallelization) {

    return new PBKDSCryptKeyService(
        new SCryptConfiguration(cpuMemoryCost, blockSize, parallelization));
  }

  @Lazy
  @Bean("SecureRandomData")
  public SecureRandomDataService secureRandom(SecureRandom secureRandom) {
    return new JCASecureRandomDataService(secureRandom);
  }

  @Lazy
  @Bean("Digest")
  public DigestService digestService(
      @Value("${cryptography.digest.algorithm:SHA_256}") DigestAlgorithm algorithm) {

    return new JCADigestService(algorithm);
  }

  @Lazy
  @Bean("Hmac")
  public MacService hmacService(
      @Value("${cryptography.mac.algorithm:HmacSHA256}") HmacAlgorithm algorithm) {

    return new JCAHmacService(algorithm);
  }
}
