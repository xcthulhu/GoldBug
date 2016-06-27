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

package gold.bug.formatting

import java.math.BigInteger
import javax.xml.bind.DatatypeConverter

object BaseConvert {

  /**
    * Convert a string from one radix to another
    * @param input The string to convert
    * @param inputRadix The radix (ie, base) of the input string
    * @param outputRadix The radix (ie, base) of the output string
    * @return The string in the base specified by the outputRadix
    */
  def convert(input: String, inputRadix: Int, outputRadix: Int): String = {
    encode(decode(input, inputRadix), outputRadix)
  }

  /**
    * Encode a byte sequence as a string of a specified radix
    * @param input The string to convert
    * @param outputRadix The radix (ie, base) of the output string
    * @return The string in the base specified by the outputRadix
    */
  def encode(input: Seq[Byte], outputRadix: Int): String = {
    outputRadix match {
      case 16 => DatatypeConverter.printHexBinary(input.toArray).toLowerCase
      case 58 => Base58.toBase58String(input)
      case 64 => DatatypeConverter.printBase64Binary(input.toArray)
      case _ =>
        Array.fill(input.takeWhile(_ == 0).length)('0').mkString ++
        new BigInteger(1, input.toArray)
          .toString(outputRadix)
          .replaceFirst("^0*", "")
    }
  }

  /**
    * Decode a string with a specified radix (ie, base) to a byte array
    * @param input The string to be decoded
    * @param inputRadix The radix (ie, base) of the input string
    * @return A byte array of data from the decoded string
    */
  def decode(input: String, inputRadix: Int): Array[Byte] = {
    inputRadix match {
      case 16 => DatatypeConverter.parseHexBinary(input.replaceFirst("^0[X,x]", ""))
      case 58 => Base58.decode(input)
      case 64 => DatatypeConverter.parseBase64Binary(input)
      case _ =>
        Array.fill[Byte](input.takeWhile(_ == '0').length)(0) ++
        new BigInteger("0" ++ input, inputRadix).toByteArray.dropWhile(_ == 0)
    }
  }
}
