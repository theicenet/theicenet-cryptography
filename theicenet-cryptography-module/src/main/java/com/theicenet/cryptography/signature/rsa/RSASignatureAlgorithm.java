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
package com.theicenet.cryptography.signature.rsa;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public enum RSASignatureAlgorithm {
  NonewithRSA,
  RIPEMD128withRSA,
  RIPEMD160withRSA,
  RIPEMD256withRSA,
  SHA1withRSA,
  SHA224withRSA,
  SHA256withRSA,
  SHA384withRSA,
  SHA512withRSA,
  SHA3_224withRSA,
  SHA3_256withRSA,
  SHA3_384withRSA,
  SHA3_512withRSA,
  SHA1withRSAandMGF1,
  SHA256withRSAandMGF1,
  SHA384withRSAandMGF1,
  SHA512withRSAandMGF1,
  SHA1WithRSA_PSS,
  SHA224withRSA_PSS,
  SHA256withRSA_PSS,
  SHA384withRSA_PSS,
  SHA512withRSA_PSS;

  @Override
  public String toString() {
    return name()
        .replace("_PSS", "/PSS")
        .replace("_", "-");
  }
}
