package com.theicenet.cryptography.test.support;

import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.commons.lang.Validate;

public class LambdaUtil {
  private LambdaUtil() {
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
        throw new RuntimeException(ex);
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

    return (t) -> {
      try {
        return throwingFunction.apply(t);
      } catch (Exception ex) {
        throw new RuntimeException(ex);
      }
    };
  }
}
