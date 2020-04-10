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
package com.theicenet.cryptography.test.support;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class RunnerUtilTest {
  @Test
  void producesTheExpectedResultCountWhenRunningConsecutiveAndAllAreDifferent() {
    // Given
    final var _100 = 100;

    // When
    final var resultSet = RunnerUtil.runConsecutively(_100, UUID::randomUUID);

    // Then
    assertThat(resultSet, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConsecutiveAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConsecutively(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet, hasSize(1));
  }

  @Test
  void producesTheExpectedResultContentWhenRunningConsecutiveAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConsecutively(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet.iterator().next(), is(equalTo(TEST_CONTENT)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenRunningConsecutiveAndNegativeNumberOfTimes() {
    // Given
    final var MINUS_100 = -100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    assertThrows(
        IllegalArgumentException.class,
        () -> RunnerUtil.runConsecutively(MINUS_100, () -> TEST_CONTENT));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConcurrentlyAndAllAreDifferent() {
    // Given
    final var _100 = 100;

    // When
    final var resultSet = RunnerUtil.runConcurrently(_100, UUID::randomUUID);

    // Then
    assertThat(resultSet, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConcurrentlyAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConcurrently(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet, hasSize(1));
  }

  @Test
  void producesTheExpectedResultContentWhenRunningConcurrentlyAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConcurrently(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet.iterator().next(), is(equalTo(TEST_CONTENT)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenRunningConcurrentlyAndNegativeNumberOfThread() {
    // Given
    final var MINUS_100 = -100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    assertThrows(
        IllegalArgumentException.class,
        () -> RunnerUtil.runConcurrently(MINUS_100, () -> TEST_CONTENT));
  }
}