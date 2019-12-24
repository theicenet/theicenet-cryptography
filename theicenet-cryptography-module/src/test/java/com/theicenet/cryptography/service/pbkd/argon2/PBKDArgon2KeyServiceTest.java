package com.theicenet.cryptography.service.pbkd.argon2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.theicenet.cryptography.test.util.HexUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

class PBKDArgon2KeyServiceTest {

  static final int KEY_LENGTH_64_BITS = 64;
  static final int KEY_LENGTH_128_BITS = 128;
  static final int KEY_LENGTH_256_BITS = 256;
  static final int KEY_LENGTH_512_BITS = 512;
  static final int KEY_LENGTH_1024_BITS = 1024;

  final String RAW = "RAW";

  final Argon2Version ARGON2_VERSION_13 = Argon2Version.ARGON2_VERSION_13;
  static final int ITERATIONS_2 = 2;
  final int MEMORY_POW_OF_TWO_10 = 10;
  static final int MEMORY_POW_OF_TWO_14 = 14;
  static final int PARALLELISM_2 = 2;

  final static String PASSWORD_1234567890_80_BITS = "1234567890";
  final String PASSWORD_0123456789_80_BITS = "0123456789";

  final static byte[] SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES =
      "GHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

  final byte[] SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES =
      "ZYXWVUTSRQPONMLKJIHG".getBytes(StandardCharsets.UTF_8);

  static final byte[] ARGON2_I_110_HASH_128_BITS =
      HexUtil.decodeHex("63352683754a88cf2a5f1da446abd5c1");

  static final byte[] ARGON2_D_110_HASH_128_BITS =
      HexUtil.decodeHex("8a97c6675f9c3e245967564a634bb815");

  static final byte[] ARGON2_ID_110_HASH_128_BITS =
      HexUtil.decodeHex("d4402a3681db6d36675655f005dae365");

  static final byte[] ARGON2_I_113_HASH_128_BITS =
      HexUtil.decodeHex("1424ebb5af0cdda9b7aace15f5ae73ba");

  static final byte[] ARGON2_D_113_HASH_128_BITS =
      HexUtil.decodeHex("49567a1ca6be78baa6374a9eb0333bc7");

  static final byte[] ARGON2_ID_113_HASH_128_BITS =
      HexUtil.decodeHex("b3e6008b1e7f54de0c690b5a14b9806c");

  static final byte[] ARGON2_I_110_HASH_256_BITS =
      HexUtil.decodeHex("ed50857669541b3debd6d5fd566182718f48760d6bd4ed8000b7bd51f1a0fc12");

  static final byte[] ARGON2_D_110_HASH_256_BITS =
      HexUtil.decodeHex("faf86ae5ddb1124ee7c60f62f711f4fabc6dd2b522eba9b309a2449ebde281c0");

  static final byte[] ARGON2_ID_110_HASH_256_BITS =
      HexUtil.decodeHex("1e061a66b66cf688d09ef3906dab405210ef6cba72eff6d68782161e4f6b0b2b");

  static final byte[] ARGON2_I_113_HASH_256_BITS =
      HexUtil.decodeHex("0b94967e7e2096d50579f9bfbd4e62a666e632a94258b1f90fb2e75b803bb2f2");

  static final byte[] ARGON2_D_113_HASH_256_BITS =
      HexUtil.decodeHex("492d435344d44991b0c7ac14852bdb565107ec3769cbaa9d85440f92d1f4af20");

  static final byte[] ARGON2_ID_113_HASH_256_BITS =
      HexUtil.decodeHex("aa932c068097546215d1a4777b8867035d99280c440b74eaae8942ed0ba89170");

  static final byte[] ARGON2_I_110_HASH_512_BITS =
      HexUtil.decodeHex(
          "94db37b5d81a3e3d74eb89eeee124843903095ab97788d8ba6277"
              + "cbd3f7e76fe24163152dae00f875db27d0271728092736307aa1d"
              + "ae9233448eea4fe4d67544");

  static final byte[] ARGON2_D_110_HASH_512_BITS =
      HexUtil.decodeHex(
          "1f8e0740bd6f02e9879e624a431dfe752f6fba7e2c9b17ad0bf81e"
              + "c27e9c0ec6367254484993445d36fefdb4c045e554dd780edadd6"
              + "312466e9a8baf85c465db");

  static final byte[] ARGON2_ID_110_HASH_512_BITS =
      HexUtil.decodeHex(
          "c1141cb03b47e7057829095009db40d7bfb0c4563640c4381fc84"
              + "d3a0ea27e1ec81899cb8776f9d1240ede79879f47dd822caba60"
              + "243adfe7c74e49063e3e92e");

  static final byte[] ARGON2_I_113_HASH_512_BITS =
      HexUtil.decodeHex(
          "0ed124f5c6af9841e389fbbdde11cd5398e15778609cb46d06090"
              + "cdbcc36b6e3d3cbc560ddcab447306a62309a3c30a3eea922585"
              + "ec603b2ddf8ebab719e76b4");

  static final byte[] ARGON2_D_113_HASH_512_BITS =
      HexUtil.decodeHex(
          "444bc01bfa850786b67508ca9cb06ac9edf3b84aee0cbe3bc4ea7"
              + "4d3192b1e45c0be3e54ed3a0a4104cff01dcd415647570c560a0"
              + "12fbd7b4b463eca41c4353a");

  static final byte[] ARGON2_ID_113_HASH_512_BITS =
      HexUtil.decodeHex(
          "42e7c2ffdd2596704612ec376b89c1d255c787869394c6d2dae529"
              + "c846aa5bb9b37d36b69a407009561816d38d49a6337002ded1b22"
              + "bf5311c4596e5b1c45778");

  static final byte[] ARGON2_I_110_HASH_1024_BITS =
      HexUtil.decodeHex(
          "3504dd371da9574d8d252f8e5af9e135589e0d6be5334a572e5e944"
              + "ce7b7a2cdb4051781ddaee60a8055bdd86fd2aba9ee62457b05aa2"
              + "997f5a6409416896f5fe678b8a6b3ae94f48afc6b580583f13a7c5"
              + "e3598964e94fcf4c30bd991391861ef6f1df5a1b873380c51dad29"
              + "bfd423515cdb048c6b5b1efa6b832cc5feb3f4d");

  static final byte[] ARGON2_D_110_HASH_1024_BITS =
      HexUtil.decodeHex(
          "1989e4f66cfb43933f57d3a901e600348199ae959e488a5c7c680fbf"
              + "0b7988189f9393a01b93b1c9f49a8d2816ed53ee0c95f29f0bd5acc8"
              + "bc97e9fc46bb58f19a270c26bfd05affa46db49c48415af58f49af00"
              + "4e5580f8686c2110b028f375a30416ee7d32c8f5f64562c8b82aae6e"
              + "a3d536007e8de362b99aa5ea8f71f3d0");

  static final byte[] ARGON2_ID_110_HASH_1024_BITS =
      HexUtil.decodeHex(
          "edcba503d6e7730c72546fc26ac08aa23c5b313a2e38a1c52e8cb1c162"
              + "a58d00abe6e638313eb33ada735aabb350cfda70ac4f6e2ee58fbcb4d9"
              + "032c4b50119704f75b628f858df0ad9aace6357303790b7e0977b58d54"
              + "925f27178d4eabd904afdfe4ec402ec73eb4b3bbeb4e7c5beea153ffb4"
              + "ce3e01f43a07cbe707637b5b");

  static final byte[] ARGON2_I_113_HASH_1024_BITS =
      HexUtil.decodeHex(
          "c266f0e7760cc34cc35b3914bf183b84c68b8190e89fb1fae9403b6"
              + "32b17b6ede1dee2e6fffbda72fcc7662034a1ffe167a4b76c7d8a4"
              + "22aa293309e8566d11f2fe0381bce57ed65c4c91bd406389fa47bc"
              + "13bb077ad5fa929d0f03699c9fae32711e748793bd14d880be2ec1"
              + "b610876fcbd9778d42ab43d20b17b81f5057829");

  static final byte[] ARGON2_D_113_HASH_1024_BITS =
      HexUtil.decodeHex(
          "89896dfe2e3495e081d6ebd012dafb090fc0e7b9c023da6daa244fd81"
              + "9dfcc65a520f1d44942549cdfc7cfcac91ebc02531d467116ac98dadc"
              + "d188c0a7432f418aa8323dcb9277563f358aa442d35c3a7aa4b666c20"
              + "e65afedd093fee53820b739f80b32b4ea63df2336472b3c213b5c606f"
              + "4a247fa4fb755d388a98fe134b0a");

  static final byte[] ARGON2_ID_113_HASH_1024_BITS =
      HexUtil.decodeHex(
          "7b7b6a87b4092b798cc6d355ce5e26be5aa7e56ba03a235ceb8da81c8a"
              + "0aeebf8da561766333f40d44521d90a1a75eaec6a30cbf79f88919185"
              + "943c67fb3cf840c42e7ebc5f284816304bdbefc8c84e02e4bd1477082"
              + "ea3e6b0e7ff729d71be32366245da3ea165f360c9be7e0304ac6981dc"
              + "c85ec7d281bed87a03c04f7b747");


  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNullPassword(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    final String NULL_PASSWORD = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                NULL_PASSWORD,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_128_BITS));
  }

  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNullSalt(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    final byte[] NULL_SALT = null;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                NULL_SALT,
                KEY_LENGTH_128_BITS));
  }

  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndNegativeKeyLength(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    final var KEY_LENGTH_MINUS_ONE = -1;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            // When
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_MINUS_ONE));
  }

  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void throwsIllegalArgumentExceptionWhenGeneratingKeyAndZeroKeyLength(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    final var KEY_LENGTH_ZERO = 0;

    // Then
    assertThrows(
        IllegalArgumentException.class,
        () ->
            pbkdKeyService.generateKey(
                PASSWORD_1234567890_80_BITS,
                SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                KEY_LENGTH_ZERO));
  }

  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void producesNotNullWhenGeneratingKey(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey, is(notNullValue()));
  }

  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void producesKeyWithRightAlgorithmWhenGeneratingKeyAndSha1And2(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getAlgorithm(), is(equalTo(argon2Type.toString())));
  }

  @ParameterizedTest
  @EnumSource(Argon2Type.class)
  void producesKeyWithRAWFormatWhenGeneratingKey(Argon2Type argon2Type) {
    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                ARGON2_VERSION_13,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS);

    // Then
    assertThat(generatedKey.getFormat(), is(equalTo(RAW)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths")
  void producesKeyWithTheRequestLengthWhenGeneratingKey(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      Integer keyLength) {

    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then
    final var generatedKeyLengthInBits = generatedKey.getEncoded().length * 8;
    assertThat(generatedKeyLengthInBits, is(equalTo(keyLength)));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths")
  void producesTheSameKeyWhenGeneratingTwoConsecutiveKeysWithTheSamePasswordSaltAndLength(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      Integer keyLength) {

    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When generating two consecutive keys with the same password, salt and length
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then the generated keys are the same
    assertThat(generatedKey_1.getEncoded(), is(equalTo(generatedKey_2.getEncoded())));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths")
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSameSaltAndLengthButDifferentPassword(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      Integer keyLength) {

    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When generating two consecutive keys with the same salt and length but different password
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_0123456789_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths")
  void producesDifferentKeysWhenGeneratingTwoConsecutiveKeysWithTheSamePasswordAndLengthButDifferentSalt(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      Integer keyLength) {

    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_14,
                PARALLELISM_2));

    // When generating two consecutive keys with the same password and length but different salt
    final var generatedKey_1 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            keyLength);
    final var generatedKey_2 =
        pbkdKeyService.generateKey(
            PASSWORD_1234567890_80_BITS,
            SALT_ZYXWVUTSRQPONMLKJIHG_20_BYTES,
            keyLength);

    // Then the generated keys are different
    assertThat(generatedKey_1.getEncoded(), is(not(equalTo(generatedKey_2.getEncoded()))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths")
  void producesTheSameKeyWhenGeneratingManyConsecutiveKeysWithTheSamePasswordSaltAndLength(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      Integer keyLength) {

    // Given
    final var _100 = 100;
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_10,
                PARALLELISM_2));

    // When generating consecutive keys with the same password, salt and length
    final var generatedKeys =
        IntStream
            .range(0, _100)
            .mapToObj(index ->
                pbkdKeyService.generateKey(
                    PASSWORD_1234567890_80_BITS,
                    SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                    keyLength))
            .map(Key::getEncoded)
            .map(BigInteger::new)
            .collect(Collectors.toUnmodifiableSet());

    // Then all keys are the same
    assertThat(generatedKeys, hasSize(1));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths")
  void producesTheSameKeyWhenGeneratingConcurrentlyManyKeysWithTheSamePasswordSaltAndLength(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      Integer keyLength) throws Exception {

    // Given
    final var _500 = 500;
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                ITERATIONS_2,
                MEMORY_POW_OF_TWO_10,
                PARALLELISM_2));

    // When generating concurrently at the same time keys with the same password, salt and length
    final var countDownLatch = new CountDownLatch(_500);
    final var executorService = Executors.newFixedThreadPool(_500);

    final var generatedKeys = new CopyOnWriteArraySet<BigInteger>();

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

              final var generatedKey =
                  pbkdKeyService.generateKey(
                      PASSWORD_1234567890_80_BITS,
                      SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
                      keyLength);

              generatedKeys.add(new BigInteger(generatedKey.getEncoded()));
            })
        );

    executorService.shutdown();
    while (!executorService.isTerminated()) {
      Thread.sleep(100);
    }

    // Then all keys are the same
    assertThat(generatedKeys, hasSize(1));
  }

  static Stream<Arguments> argumentsWithAllArgon2TypesAllArgon2VersionsAndMultipleKeyLengths() {
    return Stream
        .of(Argon2Type.values())
        .flatMap(argon2Type ->
            Stream
                .of(Argon2Version.values())
                .flatMap(argon2Version ->
                    Stream
                        .of(
                            KEY_LENGTH_64_BITS,
                            KEY_LENGTH_128_BITS,
                            KEY_LENGTH_256_BITS,
                            KEY_LENGTH_512_BITS,
                            KEY_LENGTH_1024_BITS)
                        .map(keyLength -> Arguments.of(argon2Type, argon2Version, keyLength))));
  }

  @ParameterizedTest
  @MethodSource("argumentsWithAllArgon2TypesAllArgon2VersionsSomeKeyLengthsAndExpectedGeneratedKey")
  void producesTheRightKeyWhenGeneratingKey(
      Argon2Type argon2Type,
      Argon2Version argon2Version,
      String password,
      byte[] salt,
      Integer keyLength,
      Integer iterations,
      Integer memoryPowOf,
      Integer parallelism,
      byte[] expectedGeneratedKey) {

    // Given
    final var pbkdKeyService =
        new PBKDArgon2Service(
            new Argon2Configuration(
                argon2Type,
                argon2Version,
                iterations,
                memoryPowOf,
                parallelism));

    // When
    final var generatedKey =
        pbkdKeyService.generateKey(
            password,
            salt,
            keyLength);

    // Then
    assertThat(generatedKey.getEncoded(), is(equalTo(expectedGeneratedKey)));
  }

  static Stream<Arguments> argumentsWithAllArgon2TypesAllArgon2VersionsSomeKeyLengthsAndExpectedGeneratedKey() {
    return Stream.of(
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_110_HASH_128_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_110_HASH_128_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_110_HASH_128_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_113_HASH_128_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_113_HASH_128_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_128_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_113_HASH_128_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_110_HASH_256_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_110_HASH_256_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_110_HASH_256_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_113_HASH_256_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_113_HASH_256_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_256_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_113_HASH_256_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_110_HASH_512_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_110_HASH_512_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_110_HASH_512_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_113_HASH_512_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_113_HASH_512_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_512_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_113_HASH_512_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_110_HASH_1024_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_110_HASH_1024_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_10,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_110_HASH_1024_BITS),
        Arguments.of(
            Argon2Type.ARGON2_I,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_I_113_HASH_1024_BITS),
        Arguments.of(
            Argon2Type.ARGON2_D,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_D_113_HASH_1024_BITS),
        Arguments.of(
            Argon2Type.ARGON2_ID,
            Argon2Version.ARGON2_VERSION_13,
            PASSWORD_1234567890_80_BITS,
            SALT_GHIJKLMNOPQRSTUVWXYZ_20_BYTES,
            KEY_LENGTH_1024_BITS,
            ITERATIONS_2,
            MEMORY_POW_OF_TWO_14,
            PARALLELISM_2,
            ARGON2_ID_113_HASH_1024_BITS)
    );
  }
}