/*
 * Copyright (c) 2016 Matthew P. Wampler-Doty
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import javax.xml.bind.DatatypeConverter

import gold.bug.formatting.{Base58, BaseConvert}
import org.scalatest.FunSpec

class FormattingTest extends FunSpec {
  describe(
      "Can translate hex to Base58 back and forth in test examples taken from https://github.com/cryptocoinjs/bs58/blob/master/test/fixtures.json") {
    case class Example(hex: String, base58: String)
    val examples = List(
        Example(hex = "", base58 = ""),
        Example(hex = "61", base58 = "2g"),
        Example(hex = "626262", base58 = "a3gV"),
        Example(hex = "636363", base58 = "aPEr"),
        Example(hex = "73696d706c792061206c6f6e6720737472696e67",
                base58 = "2cFupjhnEsSn59qHXstmK2ffpLv2"),
        Example(hex = "00eb15231dfceb60925886b67d065299925915aeb172c06647",
                base58 = "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
        Example(hex = "516b6fcd0f", base58 = "ABnLTmg"),
        Example(hex = "bf4f89001e670274dd", base58 = "3SEo3LWLoPntC"),
        Example(hex = "572e4794", base58 = "3EFU7m"),
        Example(hex = "ecac89cad93923c02321", base58 = "EJDM8drfXA6uyA"),
        Example(hex = "10c8511e", base58 = "Rt5zm"),
        Example(hex = "00000000000000000000", base58 = "1111111111"),
        Example(hex =
                  "801184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd206ec97e",
                base58 =
                  "5Hx15HFGyep2CfPxsJKe2fXJsCVn5DEiyoeGGF6JZjGbTRnqfiD"),
        Example(hex = "003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187",
                base58 = "16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS")
    )

    it("Translate from hex to base58 using DatatypeConverter and Base58 libraries") {
      examples.foreach(e => {
        val binary = DatatypeConverter.parseHexBinary(e.hex)
        assert(Base58.toBase58String(binary) == e.base58)
      })
    }

    it("Translate from hex to base58 using BaseConvert.convert") {
      examples.foreach(e =>
            assert(BaseConvert.convert(e.hex, 16, 58) == e.base58))
    }

    it("Translate from base58 to hex using BaseConvert.convert") {
      examples.foreach(e =>
            assert(BaseConvert.convert(e.base58, 58, 16) == e.hex))
    }

    it("Translate from base58 to base64 to hex using BaseConvert.convert") {
      examples.foreach(e =>
            assert(BaseConvert.convert(
                    BaseConvert.convert(e.base58, 58, 64), 64, 16) == e.hex))
    }

    it("Translate from base58 to decimal to hex using BaseConvert.convert") {
      examples.foreach(e =>
        assert(BaseConvert.convert(
          BaseConvert.convert(e.base58, 58, 10), 10, 16) == e.hex))
    }
  }
}
