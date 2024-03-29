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

import com.theicenet.cryptography.digest.DigestAlgorithm;
import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import com.theicenet.cryptography.key.asymmetric.dsa.JCADSAKeyService;
import com.theicenet.cryptography.key.asymmetric.rsa.JCARSAKeyService;
import com.theicenet.cryptography.key.symmetric.SymmetricKeyService;
import com.theicenet.cryptography.key.symmetric.aes.JCAAESKeyService;
import com.theicenet.cryptography.keyagreement.KeyAgreementService;
import com.theicenet.cryptography.keyagreement.SRP6ClientService;
import com.theicenet.cryptography.keyagreement.SRP6ServerService;
import com.theicenet.cryptography.keyagreement.SRP6VerifierService;
import com.theicenet.cryptography.keyagreement.ecc.ecdh.JCACEDHKeyAgreementService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.RFC5054SRP6ClientService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.RFC5054SRP6ServerService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.RFC5054SRP6VerifierService;
import com.theicenet.cryptography.keyagreement.pake.srp.v6a.SRP6StandardGroup;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

/**
 * IMPORTANT:
 * 
 *    Please note that SecureRandomDataService beans is defined in
 *    SecureRandomDataDynamicContextInitializer as they're required in some other Context
 *    initializers, which are run before than this AutoConfiguration during the Spring Boot
 *    context initialisation process.
 *
 *  Please ignore any IDE warning on this matter.
 *
 * @author Juan Fidalgo
 * @since 1.0.0
 */
@Configuration
public class StaticAutoConfiguration {

  @Lazy
  @Bean("AESKey")
  public SymmetricKeyService aesKeyService(SecureRandomDataService secureRandomDataService) {
    return new JCAAESKeyService(secureRandomDataService);
  }

  @Lazy
  @Bean("RSAKey")
  public AsymmetricKeyService rsaKeyService(SecureRandomDataService secureRandomDataService) {
    return new JCARSAKeyService(secureRandomDataService);
  }

  @Lazy
  @Bean("DSAKey")
  public AsymmetricKeyService dsaKeyService(SecureRandomDataService secureRandomDataService) {
    return new JCADSAKeyService(secureRandomDataService);
  }

  @Lazy
  @Bean("ECDHKeyAgreement")
  public KeyAgreementService ecdhKeyAgreementService() {
    return new JCACEDHKeyAgreementService();
  }

  @Lazy
  @Bean("PBKDArgon2")
  public PBKDKeyService pbkdArgon2KeyService(
      @Value("${cryptography.keyDerivationFunction.argon2.type}") Argon2Type type,
      @Value("${cryptography.keyDerivationFunction.argon2.version}") Argon2Version version,
      @Value("${cryptography.keyDerivationFunction.argon2.iterations}") Integer iterations,
      @Value("${cryptography.keyDerivationFunction.argon2.memoryPowOfTwo}") Integer memoryPowOfTwo,
      @Value("${cryptography.keyDerivationFunction.argon2.parallelism}") Integer parallelism) {

    return new PBKDArgon2KeyService(
        new Argon2Configuration(type, version, iterations, memoryPowOfTwo, parallelism));
  }

  @Lazy
  @Bean("PBKDF2")
  public PBKDKeyService pbkdF2KeyService(
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.shaAlgorithm}") PBKDF2ShaAlgorithm shaAlgorithm,
      @Value("${cryptography.keyDerivationFunction.pbkdF2WithHmacSHA.iterations}") Integer iterations) {

    return new JCAPBKDF2WithHmacSHAKeyService(new PBKDF2Configuration(shaAlgorithm, iterations));
  }

  @Lazy
  @Bean("PBKDSCrypt")
  public PBKDKeyService pbkdSCryptKeyService(
      @Value("${cryptography.keyDerivationFunction.scrypt.cpuMemoryCost}") Integer cpuMemoryCost,
      @Value("${cryptography.keyDerivationFunction.scrypt.blockSize}") Integer blockSize,
      @Value("${cryptography.keyDerivationFunction.scrypt.parallelization}") Integer parallelization) {

    return new PBKDSCryptKeyService(
        new SCryptConfiguration(cpuMemoryCost, blockSize, parallelization));
  }

  @Lazy
  @Bean("SRP6Verifier")
  public SRP6VerifierService srp6VerifierService(
      @Value("${cryptography.pake.srp.v6a.standardGroup}") SRP6StandardGroup standardGroup,
      @Value("${cryptography.pake.srp.v6a.digest.algorithm}")DigestAlgorithm digestAlgorithm) {

    return new RFC5054SRP6VerifierService(standardGroup, digestAlgorithm);
  }

  @Lazy
  @Bean("SRP6Client")
  public SRP6ClientService srp6ClientService(
      @Value("${cryptography.pake.srp.v6a.standardGroup}") SRP6StandardGroup standardGroup,
      @Value("${cryptography.pake.srp.v6a.digest.algorithm}")DigestAlgorithm digestAlgorithm,
      SecureRandomDataService secureRandomDataService) {

    return new RFC5054SRP6ClientService(standardGroup, digestAlgorithm, secureRandomDataService);
  }

  @Lazy
  @Bean("SRP6Server")
  public SRP6ServerService srp6ServerService(
      @Value("${cryptography.pake.srp.v6a.standardGroup}") SRP6StandardGroup standardGroup,
      @Value("${cryptography.pake.srp.v6a.digest.algorithm}")DigestAlgorithm digestAlgorithm,
      SecureRandomDataService secureRandomDataService) {

    return new RFC5054SRP6ServerService(standardGroup, digestAlgorithm, secureRandomDataService);
  }
}
