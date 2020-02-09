package com.theicenet.cryptography.test.support;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class HexUtilTest {

  final byte[] BYTE_ARRAY_REPRESENTATION = new byte[]{
      70, -33, 85, -21, 65, -27, 124, 39, 41, 89, -26, 80, 28, -88, 106, -78, 15,
      9, 87, 16, 34, 18, 26, -111, 69, -33, -61, 8, -5, -79, -7, 15, -123, -30,
      6, -66, 73, 52, 49, 7, -26, 7, -57, -47, -27, 4, -119, -104, -51, 42, -70,
      105, 121, 118, -61, 57, 73, 47, 127, -109, -38, 78, -90, -107, 126, -93, -23,
      88, -102, -77, 44, 103, 9, 41, 49, 60, -95, -15, -22, 125, -122, -99, -67, 71,
      -48, 75, 83, 64, -96, -15, 20, -87, -3, 47, 109, 98, 78, -16, -54, 116, -55,
      -74, 87, -69, 46, 116, -2, -43, 30, 122, -6, 35, 28, -65, -123, -66, 86, 103,
      -6, 106, 121, 104, -90, -62, 90, -115, 69, -82, -71, -80, 80, -104, 61, -44,
      67, 5, 52, -115, -108, -69, 28, 91, -86, 34, 83, 125, 85, -62, 76, -70, 99,
      -64, -124, -62, -4, -68, 28, -21, -44, 127, -92, -10, -67, 58, -79, -21, 121,
      -2, -65, -56, -12, -6, -48, -84, -73, -66, 82, -18, -78, -114, -119, 64, 76,
      -23, 118, -89, -128, -60, 33, -20, 16, 19, -103, -98, -8, -25, -74, 124, 18,
      115, -75, 0, 80, -62, 98, 93, -122, 117, 39, 121, 86, 55, -11, 62, -70, 26,
      -119, -44, -26, 78, 125, -12, 88, -126, 70, -128, 114, 22, 46, 77, -110, -115,
      -62, 120, -112, 104, 111, 123, 34, 41, 64, -114, -90, 59, 14, -46, 109, 31, -7,
      -56, 35, -98, -11, -101, 49, 123, -2, 46, -40, 17, -45, 95, 69, 58, -44, -46,
      -117, -78, -121, 80, 48, -34, -14, -17, -63, -117, 102, -52, 100, -112, -120,
      -126, 120, 104, -123, -16, 11, 3, 54, 74, -89, 23, -82, 58, -110, -107, -97, 19,
      -49, -101, -80, 75, -43, -84, -11, -118, 90, -116, 34, -27, -117, -83, -6, 73,
      -86, 41, -37, -120, -62, -77, 9, 94, 14, -123, -96, 125, -1, -115, 25, -73, 54,
      22, -31, -69, -29, -36, -27, -34, -30, 76, 125, 54, -9, -112, -102, -113, -73,
      81, -39, 102, -74, 98, -75, 83, -72, -65, -36, -56, -27, 127, -1, -44, -60, -89,
      -120, 90, -45, 36, -61, -10, -49, 81, 67, 12, 60, -88, -76, -41, -101, -3, 23,
      -86, -75, -40, 28, 114, 101, 85, 107, -13, 7, -106, 79, 85, 103, -118, 5, -90,
      80, -86, 115, -15, -15, 10, 86, 2, -58, 120, 25, -73, -12, 38, 94, 18, 22, 28,
      68, -18, 115, -88, -89, -111, -117, 39, -52, 52, -96, -11, 44, 12, 109, -78, 60,
      26, 37, 76, 45, 115, 65, -75, -98, -33, -103, 63, 46, 82, -83, -47, -41, 11, -70,
      97, -64, -53, 11, 33, 126, -39, 65, -122, -57, -28, -71, -26, 75, -111, -35, -28,
      80, 54, 117, -109, -100, 60, 122, -2, 57, 49, -111, 100, -92, -51, 83, -54, 58,
      -124, -64, -61, 47, 119, -79, 76, 18, 60, -40, -77, 47, -124, 79, -63, -35, -82,
      37, 35, 114, 31, 80, -69, -26, 126, -55, -9};

  final String HEX_REPRESENTATION =
      "46df55eb41e57c272959e6501ca86ab20f09571022121a9145dfc308fbb1f90f85e206be49343107e"
          + "607c7d1e5048998cd2aba697976c339492f7f93da4ea6957ea3e9589ab32c670929313ca1f1"
          + "ea7d869dbd47d04b5340a0f114a9fd2f6d624ef0ca74c9b657bb2e74fed51e7afa231cbf85b"
          + "e5667fa6a7968a6c25a8d45aeb9b050983dd44305348d94bb1c5baa22537d55c24cba63c084"
          + "c2fcbc1cebd47fa4f6bd3ab1eb79febfc8f4fad0acb7be52eeb28e89404ce976a780c421ec1"
          + "013999ef8e7b67c1273b50050c2625d867527795637f53eba1a89d4e64e7df4588246807216"
          + "2e4d928dc27890686f7b2229408ea63b0ed26d1ff9c8239ef59b317bfe2ed811d35f453ad4d"
          + "28bb2875030def2efc18b66cc64908882786885f00b03364aa717ae3a92959f13cf9bb04bd5"
          + "acf58a5a8c22e58badfa49aa29db88c2b3095e0e85a07dff8d19b73616e1bbe3dce5dee24c7"
          + "d36f7909a8fb751d966b662b553b8bfdcc8e57fffd4c4a7885ad324c3f6cf51430c3ca8b4d7"
          + "9bfd17aab5d81c7265556bf307964f55678a05a650aa73f1f10a5602c67819b7f4265e12161"
          + "c44ee73a8a7918b27cc34a0f52c0c6db23c1a254c2d7341b59edf993f2e52add1d70bba61c0"
          + "cb0b217ed94186c7e4b9e64b91dde4503675939c3c7afe39319164a4cd53ca3a84c0c32f77b"
          + "14c123cd8b32f844fc1ddae2523721f50bbe67ec9f7";

  @Test
  void producesRightHexFromByteArray() {
    // When
    final var hex = HexUtil.encodeHex(BYTE_ARRAY_REPRESENTATION);

    // Then
    assertThat(hex, is(equalTo(HEX_REPRESENTATION)));
  }

  @Test
  void producesRightByteArrayFromHex() {
    // When
    final var byteArray = HexUtil.decodeHex(HEX_REPRESENTATION);

    // Then
    assertThat(byteArray, is(equalTo(BYTE_ARRAY_REPRESENTATION)));
  }

  @Test
  void throwsHexExceptionWhenInvalidHex() {
    // Given
    final var INVALID_HEX_REPRESENTATION = "ABCDEFXXXYY";

    // When
    assertThrows(HexException.class, () -> HexUtil.decodeHex(INVALID_HEX_REPRESENTATION));
  }
}