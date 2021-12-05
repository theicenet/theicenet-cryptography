/*
 * Copyright 2019-2021 the original author or authors.
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
package com.theicenet.cryptography.keyagreement.pake.srp.v6a;

import org.apache.commons.lang3.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class SRP6ClientValuesA {

  private final byte[] clientPrivateValueA;
  private final byte[] clientPublicValueA;

  /**
   * @param clientPrivateValueA big-endian unsigned binary representation of the client's private value a
   * @param clientPublicValueA big-endian unsigned binary representation of the client's public value A
   */
  public SRP6ClientValuesA(byte[] clientPrivateValueA, byte[] clientPublicValueA) {
    Validate.notNull(clientPrivateValueA);
    Validate.notNull(clientPublicValueA);

    this.clientPrivateValueA = clientPrivateValueA.clone();
    this.clientPublicValueA = clientPublicValueA.clone();
  }

  public byte[] getClientPrivateValueA() {
    return clientPrivateValueA.clone();
  }

  public byte[] getClientPublicValueA() {
    return clientPublicValueA.clone();
  }
}
