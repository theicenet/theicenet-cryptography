package com.theicenet.cryptography.pbkd.argon2;

import org.bouncycastle.crypto.params.Argon2Parameters;

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
