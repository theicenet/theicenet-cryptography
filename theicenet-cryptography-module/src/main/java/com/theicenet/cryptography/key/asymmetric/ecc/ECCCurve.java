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
package com.theicenet.cryptography.key.asymmetric.ecc;

import java.util.Collection;
import java.util.List;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public enum ECCCurve {
  primeXXXv1(192, 239, 256),
  primeXXXv2(192, 239),
  primeXXXv3(192, 239),
  secpXXXk1(192, 224, 256),
  secpXXXr1(192, 224, 256, 384, 521),
  P_XXX(224, 256, 384, 521),
  c2pnbXXXv1(163),
  c2pnbXXXv2(163),
  c2pnbXXXv3(163),
  c2pnbXXXw1(176, 208, 272, 304, 368),
  c2tnbXXXv1(191, 239, 359),
  c2tnbXXXv2(191, 239),
  c2tnbXXXv3(191, 239),
  c2tnbXXXr1(431),
  sectXXXk1(163, 233, 239, 283, 409, 571),
  sectXXXr1(163, 193, 233, 283, 409, 571),
  sectXXXr2(163, 193),
  B_XXX(163, 233, 283, 409, 571),
  brainpoolpXXXr1(160, 192, 224, 256, 320, 384, 512),
  brainpoolpXXXt1(160, 192, 224, 256, 320, 384, 512);

  private final Collection<Integer> keyLengths;

  ECCCurve(Integer... keyLengths) {
    this.keyLengths = List.of(keyLengths);
  }

  public Collection<Integer> getKeyLengths() {
    return keyLengths;
  }

  @Override
  public String toString() {
    return name().replace("_", "-");
  }
}
