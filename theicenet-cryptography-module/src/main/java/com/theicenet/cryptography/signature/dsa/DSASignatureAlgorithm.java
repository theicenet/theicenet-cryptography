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
package com.theicenet.cryptography.signature.dsa;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public enum DSASignatureAlgorithm {
  NONEwithDSA,
  SHA1withDSA,
  SHA224withDSA,
  SHA256withDSA,
  SHA384withDSA,
  SHA512withDSA,
  SHA3_224withDSA,
  SHA3_256withDSA,
  SHA3_384withDSA,
  SHA3_512withDSA;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
