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
object Base58 {

  private val bigFiftyEight = BigInteger.valueOf(58L)
  private val alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  private val characterToIntegerMap = alphabet.zipWithIndex.toMap
  private val characterToBigInteger =
    (characterToIntegerMap apply _) andThen (BigInteger.valueOf(_))
  private val alphaSet = alphabet.toList.toSet

  private def reversedBase58DigitStream(n: BigInteger): Stream[Char] =
    n match {
      case BigInteger.ZERO => Stream.empty
      case _ =>
        val Array(quotient, remainder) = n.divideAndRemainder(bigFiftyEight)
        alphabet.charAt(remainder.intValue) #:: reversedBase58DigitStream(
            quotient)
    }

  /**
    * Encode a sequence of bytes as a Base58 string
    * @param input A sequence of bytes to be Base58 encoded
    * @return A Base58 output string
    */
  def toBase58String(input: Seq[Byte]): String =
    (reversedBase58DigitStream(new BigInteger(1, input.toArray)) ++
        input.takeWhile(_ == 0).map(Function.const('1'))).reverse.mkString

  /**
    * Decode a Base58 representation of a sequence of bytes
    * @param input Base58 encoded data as a string
    * @return The decoded data
    */
  def decode(input: String): Array[Byte] = {
    if (!input.forall(alphaSet.contains))
      throw new IllegalArgumentException("Input is not in Base 58")
    Array.fill[Byte](input.takeWhile(_ == '1').length)(0) ++
    input
      .dropWhile(_ == '1')
      .map(characterToBigInteger)
      .foldLeft(BigInteger.ZERO)(_.multiply(bigFiftyEight).add(_))
      .toByteArray
      .dropWhile(_ == 0)
  }
}
