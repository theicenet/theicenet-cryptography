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

import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.apache.commons.lang.Validate;

/**
 * @author Juan Fidalgo
 * @since 1.0.0
 */
public interface RunnerUtil {

  static  <T> List<T> runConsecutivelyToList(int numberOfTime, Supplier<T> supplier) {
    Validate.isTrue(numberOfTime >= 0);
    Validate.notNull(supplier);

    return IntStream
        .range(0, numberOfTime)
        .mapToObj(index -> supplier.get())
        .collect(Collectors.toUnmodifiableList());
  }

  static  <T> Set<T> runConsecutivelyToSet(int numberOfTime, Supplier<T> supplier) {
    return Set.copyOf(runConsecutivelyToList(numberOfTime, supplier));
  }

  static  <T> List<T> runConcurrentlyToList(int numberConcurrentThreads, Supplier<T> supplier) {
    Validate.isTrue(numberConcurrentThreads >= 0);
    Validate.notNull(supplier);

    final CountDownLatch countDownLatch = new CountDownLatch(numberConcurrentThreads);
    final ExecutorService executorService = Executors.newFixedThreadPool(numberConcurrentThreads);

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
            .collect(Collectors.toUnmodifiableList());

    executorService.shutdown();
    LambdaUtil
        .throwingRunnableWrapper(
            () -> executorService.awaitTermination(10, TimeUnit.SECONDS))
        .run();

    return result;
  }

  static  <T> Set<T> runConcurrentlyToSet(int numberConcurrentThreads, Supplier<T> supplier) {
    return Set.copyOf(runConcurrentlyToList(numberConcurrentThreads, supplier));
  }
}
