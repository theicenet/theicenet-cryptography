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
package com.theicenet.cryptography.cipher.asymmetric.rsa;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public enum RSAPadding {
  NoPadding,
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
