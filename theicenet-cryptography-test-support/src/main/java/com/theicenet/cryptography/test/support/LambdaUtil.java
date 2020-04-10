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

import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public class LambdaUtil {
  private LambdaUtil() {
  }

  @FunctionalInterface
  public interface ThrowingRunnable<E extends Exception> {
    void run() throws E;
  }

  public static Runnable throwingRunnableWrapper(
      ThrowingRunnable<Exception> throwingRunnable) {

    Validate.notNull(throwingRunnable);

    return () -> {
      try {
        throwingRunnable.run();
      } catch (Exception ex) {
        throw new LambdaException(ex);
      }
    };
  }

  @FunctionalInterface
  public interface ThrowingSupplier<T, E extends Exception> {
    T get() throws E;
  }

  public static <T> Supplier<T> throwingSupplierWrapper(
      ThrowingSupplier<T, Exception> throwingSupplier) {

    Validate.notNull(throwingSupplier);

    return () -> {
      try {
        return throwingSupplier.get();
      } catch (Exception ex) {
        throw new LambdaException(ex);
      }
    };
  }

  @FunctionalInterface
  public interface ThrowingFunction<T, R, E extends Exception> {
    R apply(T t) throws E;
  }

  public static <T, R> Function<T, R> throwingFunctionWrapper(
      ThrowingFunction<T, R, Exception> throwingFunction) {

    Validate.notNull(throwingFunction);

    return t -> {
      try {
        return throwingFunction.apply(t);
      } catch (Exception ex) {
        throw new LambdaException(ex);
      }
    };
  }
}
