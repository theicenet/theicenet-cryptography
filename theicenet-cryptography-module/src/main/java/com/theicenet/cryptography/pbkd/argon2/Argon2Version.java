package com.theicenet.cryptography.pbkd.argon2;

import org.bouncycastle.crypto.params.Argon2Parameters;

public enum Argon2Version {
  ARGON2_VERSION_10(Argon2Parameters.ARGON2_VERSION_10),
  ARGON2_VERSION_13(Argon2Parameters.ARGON2_VERSION_13);

  private final int versionCode;

  Argon2Version(int versionCode) {
    this.versionCode = versionCode;
  }

  public int getVersionCode() {
    return versionCode;
  }
}
