/*
 * Copyright 2019-2021 the original author or authors.
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
package com.theicenet.cryptography.keyagreement.pake.srp.v6a;

import static com.theicenet.cryptography.util.ByteArraysUtil.toBigInteger;
import static com.theicenet.cryptography.test.support.HexUtil.decodeHex;

import com.theicenet.cryptography.digest.DigestAlgorithm;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Testin vectors described in RFC 5054 specification, Appendix B
 *
 * @see <a href="https://tools.ietf.org/html/rfc5054">Specification: RFC 5054</a>
 *
 * This  RFC 5054 test vectors can be used to validate a SRP6a implementation fully comply with the
 * RFC 5054 specification by checking the implementation works as decribed in the specification
 *  when using the RFC 5054 testing vectors
 *
 * Please note that the RFC 5054 Appendix B doesn't provide with any expected values for M1, M2 and
 * Session Key. For this reason this this testing vectors neither does it.
 *
 * @author Juan Fidalgo
 */
interface SRP6RFC5054TestingVectors {
  byte[] IDENTITY = "alice".getBytes(StandardCharsets.UTF_8);
  byte[] PASSWORD = "password123".getBytes(StandardCharsets.UTF_8);

  byte[] SALT = decodeHex("BEB25379D1A8581EB5A727673A2441EE");

  SRP6StandardGroup SG_1024 = SRP6StandardGroup.SG_1024;
  BigInteger N = SG_1024.getN();
  BigInteger g = SG_1024.getG();

  DigestAlgorithm HASH_SHA_1 = DigestAlgorithm.SHA_1;

  BigInteger a =
      toBigInteger(decodeHex("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"));

  BigInteger b =
      toBigInteger(decodeHex("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20"));

  BigInteger EXPECTED_K =
      toBigInteger(decodeHex("7556AA045AEF2CDD07ABAF0F665C3E818913186F"));

  BigInteger EXPECTED_X =
      toBigInteger(decodeHex("94B7555AABE9127CC58CCF4993DB6CF84D16C124"));

  BigInteger EXPECTED_VERIFIER =
      toBigInteger(decodeHex(
          "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4"
              + "729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA"
              + "53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E209"
              + "9AFB"));

  BigInteger EXPECTED_A =
      toBigInteger(decodeHex(
          "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358"
              + "A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE"
              + "087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769"
              + "447B"));

  BigInteger EXPECTED_B =
      toBigInteger(decodeHex(
          "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652"
              + "236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37"
              + "089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B11"
              + "7B58"));

  BigInteger EXPECTED_U =
      toBigInteger(decodeHex("CE38B9593487DA98554ED47D70A7AE5F462EF019"));

  BigInteger EXPECTED_S =
      toBigInteger(decodeHex(
          "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A"
              + "6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F34"
              + "99B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA68"
              + "6E5A"));
}
