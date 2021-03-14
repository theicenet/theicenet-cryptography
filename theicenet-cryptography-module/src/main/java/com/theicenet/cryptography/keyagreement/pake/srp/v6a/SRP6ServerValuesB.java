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

import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.1.0
 */
public class SRP6ServerValuesB {

  private final byte[] serverPrivateValueB;
  private final byte[] serverPublicValueB;

  /**
   * @param serverPrivateValueB big-endian unsigned binary representation of the server's private value b
   * @param serverPublicValueB big-endian unsigned binary representation of the server's public value B
   */
  public SRP6ServerValuesB(byte[] serverPrivateValueB, byte[] serverPublicValueB) {
    Validate.notNull(serverPrivateValueB);
    Validate.notNull(serverPublicValueB);

    this.serverPrivateValueB = serverPrivateValueB.clone();
    this.serverPublicValueB = serverPublicValueB.clone();
  }

  public byte[] getServerPrivateValueB() {
    return serverPrivateValueB.clone();
  }

  public byte[] getServerPublicValueB() {
    return serverPublicValueB.clone();
  }
}
