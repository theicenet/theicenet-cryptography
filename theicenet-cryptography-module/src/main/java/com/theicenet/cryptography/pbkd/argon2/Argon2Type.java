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
package com.theicenet.cryptography.pbkd.argon2;

import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public enum Argon2Type {
  ARGON2_D(Argon2Parameters.ARGON2_d),
  ARGON2_I(Argon2Parameters.ARGON2_i),
  ARGON2_ID(Argon2Parameters.ARGON2_id);

  private final int typeCode;

  Argon2Type(int typeCode) {
    this.typeCode = typeCode;
  }

  public int getTypeCode() {
    return typeCode;
  }
}
