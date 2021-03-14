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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class SRP6ServerValuesBTest {

  final byte[] PRIVATE_VALUE = new byte[]{11};
  final byte[] PUBLIC_VALUE = new byte[]{33};

  @Test
  void checkConstructorPrivateValueIsImmutable() {
    // Given
    final var MUTABLE_IN_CONSTRUCTOR_PRIVATE_VALUE = PRIVATE_VALUE.clone();

    final var srp6ServerValuesB =
        new SRP6ServerValuesB(
            MUTABLE_IN_CONSTRUCTOR_PRIVATE_VALUE,
            PUBLIC_VALUE);

    // When
    MUTABLE_IN_CONSTRUCTOR_PRIVATE_VALUE[0] += 1;

    // Then
    assertThat(srp6ServerValuesB.getServerPrivateValueB(), is(equalTo(PRIVATE_VALUE)));
  }

  @Test
  void checkConstructorPublicValueIsImmutable() {
    // Given
    final var MUTABLE_IN_CONSTRUCTOR_PUBLIC_VALUE = PUBLIC_VALUE.clone();

    final var srp6ServerValuesB =
        new SRP6ServerValuesB(
            PRIVATE_VALUE,
            MUTABLE_IN_CONSTRUCTOR_PUBLIC_VALUE);

    // When
    MUTABLE_IN_CONSTRUCTOR_PUBLIC_VALUE[0] += 1;

    // Then
    assertThat(srp6ServerValuesB.getServerPublicValueB(), is(equalTo(PUBLIC_VALUE)));
  }

  @Test
  void checkReturnedPrivateValueDoesNotBreakImmutability() {
    // Given
    final var srp6ServerValuesB =
        new SRP6ServerValuesB(
            PRIVATE_VALUE,
            PUBLIC_VALUE);

    // When
    srp6ServerValuesB.getServerPrivateValueB()[0] += 1;

    // Then
    assertThat(srp6ServerValuesB.getServerPrivateValueB(), is(equalTo(PRIVATE_VALUE)));
  }

  @Test
  void checkReturnedPublicValueDoesNotBreakImmutability() {
    // Given
    final var srp6ServerValuesB =
        new SRP6ServerValuesB(
            PRIVATE_VALUE,
            PUBLIC_VALUE);

    // When
    srp6ServerValuesB.getServerPublicValueB()[0] += 1;

    // Then
    assertThat(srp6ServerValuesB.getServerPublicValueB(), is(equalTo(PUBLIC_VALUE)));
  }
}