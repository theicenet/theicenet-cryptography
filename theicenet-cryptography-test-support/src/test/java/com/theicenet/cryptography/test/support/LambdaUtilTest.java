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
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import com.theicenet.cryptography.test.support.LambdaUtil.ThrowingFunction;
import com.theicenet.cryptography.test.support.LambdaUtil.ThrowingRunnable;
import com.theicenet.cryptography.test.support.LambdaUtil.ThrowingSupplier;
import org.junit.jupiter.api.Test;

/**
 * @author Juan Fidalgo
 */
class LambdaUtilTest {

  final Exception TEST_CHECKED_EXCEPTION = new Exception("Test Checked Exception");
  final String TEST_CONTENT = "TEST_CONTENT";

  @Test
  void wrapsProperlyANonThrowingExceptionRunnable() {
    // Given
    final ThrowingRunnable<Exception> throwingCheckedExceptionRunnable = () -> {};

    // When
    final var producedRunnable =
        LambdaUtil.throwingRunnableWrapper(throwingCheckedExceptionRunnable);

    // Then
    try {
      producedRunnable.run();
    } catch (Exception e) {
      fail("Wrapper of non throwing exception runnable has thrown exception");
    }
  }

  @Test
  void wrapsProperlyAThrowingCheckedExceptionRunnable() {
    // Given
    final ThrowingRunnable<Exception> throwingCheckedExceptionRunnable =
        () -> {
          throw TEST_CHECKED_EXCEPTION;
        };

    // When
    final var producedRunnable =
        LambdaUtil.throwingRunnableWrapper(throwingCheckedExceptionRunnable);

    // Then
    assertThrows(LambdaException.class, producedRunnable::run);
  }

  @Test
  void wrapsProperlyANonThrowingExceptionSupplier() {
    // Given
    final ThrowingSupplier<String, Exception> throwingCheckedExceptionSupplier = () -> TEST_CONTENT;

    // When
    final var producedSupplier =
        LambdaUtil.throwingSupplierWrapper(throwingCheckedExceptionSupplier);

    // Then
    assertThat(producedSupplier.get(), is(equalTo(TEST_CONTENT)));
  }

  @Test
  void wrapsProperlyAThrowingCheckedExceptionSupplier() {
    // Given
    final ThrowingSupplier<String, Exception> throwingCheckedExceptionSupplier =
        () -> {
          throw TEST_CHECKED_EXCEPTION;
        };

    // When
    final var producedSupplier =
        LambdaUtil.throwingSupplierWrapper(throwingCheckedExceptionSupplier);

    // Then
    assertThrows(LambdaException.class, producedSupplier::get);
  }

  @Test
  void wrapsProperlyANonThrowingExceptionFunction() {
    // Given
    final ThrowingFunction<String, String, Exception> throwingCheckedExceptionFunction = t -> t;

    // When
    final var producedFunction =
        LambdaUtil.throwingFunctionWrapper(throwingCheckedExceptionFunction);

    // Then
    assertThat(producedFunction.apply(TEST_CONTENT), is(equalTo(TEST_CONTENT)));
  }

  @Test
  void wrapsProperlyAThrowingCheckedExceptionFunction() {
    // Given
    final ThrowingFunction<String, String, Exception> throwingCheckedExceptionFunction =
        t -> {
          throw TEST_CHECKED_EXCEPTION;
        };

    // When
    final var producedFunction =
        LambdaUtil.throwingFunctionWrapper(throwingCheckedExceptionFunction);

    // Then
    assertThrows(LambdaException.class, () -> producedFunction.apply("test"));
  }
}