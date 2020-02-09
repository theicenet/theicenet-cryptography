package com.theicenet.cryptography.test.support;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;

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