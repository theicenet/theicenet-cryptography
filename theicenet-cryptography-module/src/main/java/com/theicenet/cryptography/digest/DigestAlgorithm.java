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
package com.theicenet.cryptography.digest;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public enum DigestAlgorithm {
  MD5,
  SHA_1,
  SHA_224,
  SHA_256,
  SHA_384,
  SHA_512,
  SHA3_224,
  SHA3_256,
  SHA3_384,
  SHA3_512,
  KECCAK_224,
  KECCAK_256,
  KECCAK_288,
  KECCAK_384,
  KECCAK_512,
  Whirlpool,
  Tiger,
  SM3,
  Blake2b_160,
  Blake2b_256,
  Blake2b_384,
  Blake2b_512,
  Blake2s_128,
  Blake2s_160,
  Blake2s_224,
  Blake2s_256,
  RIPEMD128,
  RIPEMD160,
  RIPEMD256,
  RIPEMD320;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
