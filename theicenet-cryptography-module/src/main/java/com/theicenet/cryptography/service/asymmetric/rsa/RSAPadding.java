package com.theicenet.cryptography.service.asymmetric.rsa;

public enum RSAPadding {
  PKCS1Padding,
  OAEPWithMD5AndMGF1Padding,
  OAEPWithSHA1AndMGF1Padding,
  OAEPWithSHA224AndMGF1Padding,
  OAEPWithSHA256AndMGF1Padding,
  OAEPWithSHA384AndMGF1Padding,
  OAEPWithSHA512AndMGF1Padding,
  OAEPWithSHA3_224AndMGF1Padding,
  OAEPWithSHA3_256AndMGF1Padding,
  OAEPWithSHA3_384AndMGF1Padding,
  OAEPWithSHA3_512AndMGF1Padding,
  ISO9796_1Padding;

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
