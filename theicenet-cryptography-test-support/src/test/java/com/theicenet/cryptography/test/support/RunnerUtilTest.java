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
  void producesTheExpectedResultCountWhenRunningConsecutiveToListAndAllAreDifferent() {
    // Given
    final var _100 = 100;

    // When
    final var resultList = RunnerUtil.runConsecutivelyToList(_100, UUID::randomUUID);

    // Then
    assertThat(resultList, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConsecutiveToListAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultList = RunnerUtil.runConsecutivelyToList(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultList, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultContentWhenRunningConsecutiveToListAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultList = RunnerUtil.runConsecutivelyToList(_100, () -> TEST_CONTENT);

    // Then
    resultList.forEach(result -> assertThat(result, is(equalTo(TEST_CONTENT))));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenRunningConsecutiveToListAndNegativeNumberOfTimes() {
    // Given
    final var MINUS_100 = -100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> RunnerUtil.runConsecutivelyToList(MINUS_100, () -> TEST_CONTENT)); // When
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConsecutiveToSetAndAllAreDifferent() {
    // Given
    final var _100 = 100;

    // When
    final var resultSet = RunnerUtil.runConsecutivelyToSet(_100, UUID::randomUUID);

    // Then
    assertThat(resultSet, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConsecutiveToSetAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConsecutivelyToSet(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet, hasSize(1));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConcurrentlyToListAndAllAreDifferent() {
    // Given
    final var _100 = 100;

    // When
    final var resultList = RunnerUtil.runConcurrentlyToList(_100, UUID::randomUUID);

    // Then
    assertThat(resultList, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConcurrentlyToListAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultList = RunnerUtil.runConcurrentlyToList(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultList, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultContentWhenRunningConcurrentlyToListAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultList = RunnerUtil.runConcurrentlyToList(_100, () -> TEST_CONTENT);

    // Then
    resultList.forEach(result -> assertThat(result, is(equalTo(TEST_CONTENT))));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenRunningConcurrentlyToListAndNegativeNumberOfThread() {
    // Given
    final var MINUS_100 = -100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> RunnerUtil.runConcurrentlyToList(MINUS_100, () -> TEST_CONTENT)); // When
  }

  @Test
  void producesTheExpectedResultContentWhenRunningConsecutiveToSetAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConsecutivelyToSet(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet.iterator().next(), is(equalTo(TEST_CONTENT)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenRunningConsecutiveToSetAndNegativeNumberOfTimes() {
    // Given
    final var MINUS_100 = -100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> RunnerUtil.runConsecutivelyToSet(MINUS_100, () -> TEST_CONTENT)); // When
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConcurrentlyToSetAndAllAreDifferent() {
    // Given
    final var _100 = 100;

    // When
    final var resultSet = RunnerUtil.runConcurrentlyToSet(_100, UUID::randomUUID);

    // Then
    assertThat(resultSet, hasSize(_100));
  }

  @Test
  void producesTheExpectedResultCountWhenRunningConcurrentlyToSetAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConcurrentlyToSet(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet, hasSize(1));
  }

  @Test
  void producesTheExpectedResultContentWhenRunningConcurrentlyToSetAndAllAreEqual() {
    // Given
    final var _100 = 100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // When
    final var resultSet = RunnerUtil.runConcurrentlyToSet(_100, () -> TEST_CONTENT);

    // Then
    assertThat(resultSet.iterator().next(), is(equalTo(TEST_CONTENT)));
  }

  @Test
  void throwsIllegalArgumentExceptionWhenRunningConcurrentlyToSetAndNegativeNumberOfThread() {
    // Given
    final var MINUS_100 = -100;
    final var TEST_CONTENT = "TEST_CONTENT";

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () -> RunnerUtil.runConcurrentlyToSet(MINUS_100, () -> TEST_CONTENT)); // When
  }
}