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
 * Genetic testing case with all input and output test vectors for a valid SRP6a testing scenario.
 *
 * This test vectors can be used to validate the correctness of any SRP6a implementation
 *
 * @author Juan Fidalgo
 */
interface SRP6GenericTestingVectors {
  byte[] IDENTITY = "testIdentity".getBytes(StandardCharsets.UTF_8);
  byte[] PASSWORD = "testPassword123".getBytes(StandardCharsets.UTF_8);

  byte[] SALT = decodeHex("73FDFC0AEA06935D2C8C28354B9A1125");

  SRP6StandardGroup SG_2048 = SRP6StandardGroup.SG_2048;
  BigInteger N = SG_2048.getN();
  BigInteger g = SG_2048.getG();

  DigestAlgorithm HASH_SHA_256 = DigestAlgorithm.SHA_256;

  BigInteger a =
      toBigInteger(decodeHex(
          "2CDD032D2F30FE4A1D40EE5CFA90737025E18CCD3D856F0C587CE98A3BFE0674A55296A10C5E50D8130BB776"
              + "3BD36E9222440A6EC7C0187A5595A3ABEF3B0F6E413819CBFB2C5F974976167460DFCEAD9F43260142"
              + "4080928868C4DADF524BAC121AFFBD782A8968449717FCC25F354B1EC2674F082530FE3D27C11800DE"
              + "BE02EF4BE5B6D459582D6752C83F0D6030F7A2B5BAAA99318958B687587EB2F827311C4405D7768DD3"
              + "A65F993F0DFBC9EDEA392AAFC4FA17DA6C19E980C3E2FB023CA167BA4C4E16204AA61DE8DF9D83C823"
              + "07893CE30DFA07EEF6572EA0293B3555208C9DB594FC6F4E8DAC6A69F9EEC515063CC8EB3BBB59268D"
              + "D2579DD99A58BE"));

  BigInteger b =
      toBigInteger(decodeHex(
          "194D6939D17CF6BE91F9CA9CE22A0E226880BF7872D377BC3EEE760159008801A11D2CE4F42B268E02997982"
              + "7BBD262791F360891839124012A72B67925DB2AC84BEC8976C1431DC16585EF09E77E04146D15B7424"
              + "10C0FCC68A67B0CEC069840020A4B808BCF1471A98EDA126601F11D56F9A9CE82B45B87F95E689FED0"
              + "7EF4093BAD1176038CB2A3D16BB2E55FB5346059886138B29FED7F404544178076DD6A7FB487F32C1C"
              + "A38ABFEEAAA33A06449BC591D0442E9963EE9DFAD2E721C98FDA251784B481EDA8A3E59D379E5CDEC9"
              + "77E7428C5B7BEEBAA6E1CDF81B5C14568B184E149C261CBEEF1F5E3970645DE151AE1C2EE1F9D04029"
              + "E75B4CD783F24E"));

  BigInteger EXPECTED_K =
      toBigInteger(decodeHex("05B9E8EF059C6B32EA59FC1D322D37F04AA30BAE5AA9003B8321E21DDB04E300"));

  BigInteger EXPECTED_X =
      toBigInteger(decodeHex("CB553439788E43F101591C0F11CEF731D69AD65DB9696797C62FD60BDC698CA5"));

  BigInteger EXPECTED_VERIFIER =
      toBigInteger(decodeHex(
          "9649D745C12451E7B652BE86FC9C24597881D56231709E5F9197E998FBD7BB6A5A44F1FDFA20A110CABF61E9"
              + "5A4D46BE3699E09791F2346B61CBF8A1B3DC1E91178A52F1A6B6FE6EDA63C68566B7020BB1871D7544"
              + "E4F6F3C4526149258B5B8EDBB4EE0DDB52563ADD314A952DDD8CD4AF7A9E31E8A0738BC310EC6CCA9E"
              + "16003A70947FB9C2C7D4C20806A9D44EE4CBD126A189B4F2906845EDFB3CFEB7794488712B44DB3EFE"
              + "FD47339898653682E95F2B70A38C1F678C90B19579FBC7CE048727B4269B40CC4773FD3324BBB30744"
              + "9EC8E25E52925DF8254AF5B9116A93401263FA451407ECD6F0846423A9531CCFB205A031C4049877FB"
              + "52D232E38AF953"
      ));

  BigInteger EXPECTED_A =
      toBigInteger(decodeHex(
          "7F35FA7767ECCF39AD7CEB1E23179933421D5858D9484D0C052AF5BB601BA3125E855D286C0078B66A4BCED4"
              + "A76BF2477B588C61C5A5A074D54FADC64C12C45F94DF263BEB57E4C659817EE1D311E197B219207782"
              + "7DFE83C6163BB04AC26B4098ADF59C4DFDADB1E811E152CE053F0A5AFD75097D0B130AE8EBCDB5EB2F"
              + "8D632D017B2F0B487EC11B1097AB447E082DA8950588A53946611249D67B8FD67AF1A6CA9F8E3EC843"
              + "B248CC033A863F7DAD06A6883B32DA3A98FB3E6C56AFA7B6DF5FC2C1D1B62AAC25C553C62CE90A3417"
              + "D2D4F6EA59B1F60382A56464BB3514CB62FA207BF7309698CCBC43945236077AC1407A9C913A66698B"
              + "85C6A830958FBD"));

  BigInteger EXPECTED_B =
      toBigInteger(decodeHex(
          "2655975C9039C313C1EDBDE4A17B8BCD72E844C9EA989ABE2C9030ADC53889139D4B89803BA82F4382001F1E"
              + "3D54BB51DEFF546AF1CB7289DBB7AC164902AB3DD6F67C8AE46ABCBAF88BAA934613D3AA9A04F210D1"
              + "AA5FB28D55A4DEEFD0C61431F4AA1AB15EB2CBBE1FE6A9A4B72623DD64EDA087736B118FD1F15883A7"
              + "5A1D89B178C490AFCF2482E2B1C84982BB56A5B6C0288FBF639F26F8AFA337F9B322C02C0551BFE5AE"
              + "202BC1EADA3B9E27712FB9261C178DD497261A073757B1D0D8EF71C11C05F2C3614589C3D85F31BE9A"
              + "E2FE17CC599FE71515E3C2104AB7F3D47BF1E75566A2CBDC3F829857F3F1661FEA1FCDE8FED5643AFB"
              + "E916CEC9035DB7"));

  BigInteger EXPECTED_U =
      toBigInteger(decodeHex("39466CBA90A0C09926F1BA71BA9534626BA083E2642D8FC0604972FDBA5A7369"));

  BigInteger EXPECTED_S =
      toBigInteger(decodeHex(
          "3334DCAF74F5829E724E0E4A9A53ED1CFEF857C917EF706B74E8D488250ACD52F30D1CE57C7C06D76661DF68"
              + "98C4F08B46CC71F9327D07B0024E779FC3BE79ADA311996D95FAD761BABFA253D07EE55A53A8E196D4"
              + "385E73658DFCE492CDAA87067A5AA898B626E48954BF24DA781B700FA8B86E7D9DF1D0A94A4C5FBFE8"
              + "52C3AC998CEA4C5905F6B455D55CBDDB22DC5F80BD6D0A724B050D83868DE33DD04D58097CF8BB682A"
              + "1F7C126A4453F70024128D6D932DDE152FD43758E0CD7854EECADA8046E4CA4CD67784F18F779DC0F0"
              + "E5BFB18F72C8E5C1FF08C360421D0170E50F29BC65B1D82568981A6A1210A50493600FC2B3AE21D3EF"
              + "EEB45977098135"));

  BigInteger EXPECTED_M1 =
      toBigInteger(decodeHex("CFC4B73AA61A0C6952A323AA3C7B05F85728675A04CC01F5CDD2CB8953C9FA24"));

  BigInteger EXPECTED_M2 =
      toBigInteger(decodeHex("87D890E6CFA72F362283FAD6143725119FBE407A652474EEEE58A6DC352C6416"));

  BigInteger EXPECTED_SESSION_KEY =
      toBigInteger(decodeHex("C58E4DF85BD931A8D89AC6D5AD2645868F649D39BC6F6BD4D28C55D958ABAFE9"));
}
