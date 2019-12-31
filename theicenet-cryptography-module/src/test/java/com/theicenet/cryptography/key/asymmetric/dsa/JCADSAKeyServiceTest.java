package com.theicenet.cryptography.key.asymmetric.dsa;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JCADSAKeyServiceTest {

  final String DSA = "DSA";
  final String X_509 = "X.509";
  final String PKCS_8 = "PKCS#8";
  final int KEY_LENGTH_1024_BITS = 1024;
  final int KEY_LENGTH_2048_BITS = 2048;
  final int KEY_LENGTH_3072_BITS = 3072;

  DSAKeyService dsaKeyService;

  @BeforeEach
  void setUp() {
    dsaKeyService = new JCADSAKeyService(new SecureRandom());
  }

  @Test
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndInvalidKeyLength() {
    // Given
    final var KEY_LENGTH_MINUS_ONE = -1;

    // When generating key and invalid key length
    // Then throws IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      dsaKeyService.generateKey(KEY_LENGTH_MINUS_ONE);
    });
  }

  @Test
  void producesNotNullKeyPairWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair, is(notNullValue()));
  }

  @Test
  void producesNotNullPublicKeyWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPublic(), is(notNullValue()));
  }

  @Test
  void producesNotNullPrivateKeyWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPrivate(), is(notNullValue()));
  }

  @Test
  void producesPublicKeyWithDSAAlgorithmWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPublic().getAlgorithm(), is(equalTo(DSA)));
  }

  @Test
  void producesPrivateKeyWithDSAAlgorithmWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPrivate().getAlgorithm(), is(equalTo(DSA)));
  }

  @Test
  void producesPublicKeyWithX509FormatWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPublic().getFormat(), is(equalTo(X_509)));
  }

  @Test
  void producesPrivateKeyWithPKCS8FormatWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPrivate().getFormat(), is(equalTo(PKCS_8)));
  }

  @Test
  void producesPublicKeyWithContentWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded(), is(notNullValue()));
  }

  @Test
  void producesPrivateKeyWithContentWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded(), is(notNullValue()));
  }

  @Test
  void producesPublicKeyWithNonEmptyContentWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPublic().getEncoded().length, is(greaterThan(0)));
  }

  @Test
  void producesPrivateKeyWithNonEmptyContentWhenGeneratingKey() {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(KEY_LENGTH_1024_BITS);

    // Then
    assertThat(generatedKeyPair.getPrivate().getEncoded().length, is(greaterThan(0)));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS, KEY_LENGTH_3072_BITS})
  void producesPublicKeyWithTheRightModulusLengthWhenGeneratingKey(int keyLength) throws Exception {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(keyLength);

    // Then
    final var keyFactory = KeyFactory.getInstance(DSA);
    final var dsaPublicKeySpec = keyFactory.getKeySpec(generatedKeyPair.getPublic(), DSAPublicKeySpec.class);

    assertThat(dsaPublicKeySpec.getP().bitLength(), is(equalTo(keyLength)));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS, KEY_LENGTH_3072_BITS})
  void producesPrivateKeyWithTheRightModulusLengthWhenGeneratingKey(int keyLength) throws Exception {
    // When
    final var generatedKeyPair = dsaKeyService.generateKey(keyLength);

    // Then
    final var keyFactory = KeyFactory.getInstance(DSA);
    final var dsaPrivateKeySpec = keyFactory.getKeySpec(generatedKeyPair.getPrivate(), DSAPrivateKeySpec.class);

    assertThat(dsaPrivateKeySpec.getP().bitLength(), is(equalTo(keyLength)));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS})
  void producesDifferentPublicKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(int keyLength) {
    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = dsaKeyService.generateKey(keyLength);
    final var generatedKeyPair_2 = dsaKeyService.generateKey(keyLength);

    // Then the generated public keys are different
    assertThat(generatedKeyPair_1.getPublic(), is(not(equalTo(generatedKeyPair_2.getPublic()))));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS})
  void producesDifferentPrivateKeysWhenGeneratingTwoConsecutiveKeysWithTheSameLength(int keyLength) {
    // When generating two consecutive key pairs with the same length
    final var generatedKeyPair_1 = dsaKeyService.generateKey(keyLength);
    final var generatedKeyPair_2 = dsaKeyService.generateKey(keyLength);

    // Then the generated private keys are different
    assertThat(generatedKeyPair_1.getPrivate(), is(not(equalTo(generatedKeyPair_2.getPrivate()))));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS})
  void producesDifferentPublicKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength(int keyLength) {
    // Given
    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatePublicKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> dsaKeyService.generateKey(keyLength))
            .map(KeyPair::getPublic)
            .collect(Collectors.toUnmodifiableSet());

    // Then all public keys have been generated and all them are different
    assertThat(generatePublicKeys, hasSize(_100));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS})
  void producesDifferentPrivateKeysWhenGeneratingManyConsecutiveKeysWithTheSameLength(int keyLength) {
    // Given
    final var _100 = 100;

    // When generating consecutive key pairs with the same length
    final var generatePrivateKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index -> dsaKeyService.generateKey(keyLength))
            .map(KeyPair::getPrivate)
            .collect(Collectors.toUnmodifiableSet());

    // Then all private key have been generated and all them are different
    assertThat(generatePrivateKeys, hasSize(_100));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS})
  void producesDifferentPublicKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength(int keyLength) throws Exception {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedPublicKeys = new CopyOnWriteArraySet<PublicKey>();

    IntStream
        .range(0, _500)
        .forEach(index ->
            executorService.execute(() -> {
              countDownLatch.countDown();
              try {
                countDownLatch.await();
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
              }

              final var keyPair = dsaKeyService.generateKey(keyLength);
              generatedPublicKeys.add(keyPair.getPublic());
            }));

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // When generating concurrently at the same time key pairs with the same length
    assertThat(generatedPublicKeys, hasSize(_500));
  }

  @ParameterizedTest
  @ValueSource(ints = {KEY_LENGTH_1024_BITS, KEY_LENGTH_2048_BITS})
  void producesDifferentPrivateKeysWhenGeneratingConcurrentlyManyKeysWithTheSameLength(int keyLength) throws Exception {
    // Given
    final var _500 = 500;

    // When generating concurrently at the same time key pairs with the same length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedPrivateKeys = new CopyOnWriteArraySet<PrivateKey>();

    IntStream
        .range(0, _500)
        .forEach(index ->
            executorService.execute(() -> {
              countDownLatch.countDown();
              try {
                countDownLatch.await();
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
              }

              final var keyPair = dsaKeyService.generateKey(keyLength);
              generatedPrivateKeys.add(keyPair.getPrivate());
            }));

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all private keys have been generated and all them are different
    assertThat(generatedPrivateKeys, hasSize(_500));
  }
}