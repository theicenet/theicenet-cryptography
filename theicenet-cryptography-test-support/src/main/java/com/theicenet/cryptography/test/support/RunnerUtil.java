package com.theicenet.cryptography.test.support;

import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.apache.commons.lang.Validate;

public class RunnerUtil {
  private RunnerUtil() {
  }

  public static  <T> Set<T> runConsecutively(int numberOfTime, Supplier<T> supplier) {
    Validate.isTrue(numberOfTime >= 0);
    Validate.notNull(supplier);

    return IntStream
        .range(0, numberOfTime)
        .mapToObj(index -> supplier.get())
        .collect(Collectors.toUnmodifiableSet());
  }

  public static  <T> Set<T> runConcurrently(int numberConcurrentThreads, Supplier<T> supplier) {
    Validate.isTrue(numberConcurrentThreads >= 0);
    Validate.notNull(supplier);

    final var countDownLatch = new CountDownLatch(numberConcurrentThreads);
    final var executorService = Executors.newFixedThreadPool(numberConcurrentThreads);

    final var futureResult =
        IntStream
              .range(0, numberConcurrentThreads)
              .mapToObj(index -> (Callable<T>) () -> {
                countDownLatch.countDown();
                LambdaUtil
                    .throwingRunnableWrapper(countDownLatch::await)
                    .run();

                return supplier.get();
              })
              .map(executorService::submit)
              .collect(Collectors.toUnmodifiableList());

    final var result =
        futureResult.stream()
            .map(future -> LambdaUtil.throwingSupplierWrapper(future::get))
            .map(Supplier::get)
            .collect(Collectors.toUnmodifiableSet());

    executorService.shutdown();
    LambdaUtil
        .throwingRunnableWrapper(
            () -> executorService.awaitTermination(10, TimeUnit.SECONDS))
        .run();

    return result;
  }
}
