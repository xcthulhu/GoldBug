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

package gold.bug.addresses

import gold.bug.HashUtil
import gold.bug.formatting.BaseConvert
import gold.bug.secp256k1.Curve.{PrivateKey, PublicKey}

/**
  * See: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
  */
class BitCoinAddress(
    val version: Byte, val hash: Seq[Byte], val checksum: Seq[Byte]) {
  if (hash.length != 20)
    throw new SecurityException(
        "Hash must be the output of RIPEMD160, so it must have 20 bytes")
  if (HashUtil
        .sha256(HashUtil.sha256(Array[Byte](version) ++ hash))
        .take(4)
        .toSeq != checksum)
    throw new SecurityException(
        "BitCoin address does not contain a valid checksum")

  /**
    * Output a byte array representation of the BitCoin Address
    * @return
    */
  def toByteArray: Array[Byte] = Array[Byte](version) ++ hash ++ checksum

  //noinspection ComparingUnrelatedTypes
  def canEqual(other: Any): Boolean = other.isInstanceOf[BitCoinAddress]

  override def equals(other: Any): Boolean = other match {
    case that: BitCoinAddress =>
      (that canEqual this) && version == that.version && hash == that.hash &&
      checksum == that.checksum
    case _ => false
  }

  override def hashCode(): Int =
    Seq(version, hash, checksum)
      .map(_.hashCode())
      .foldLeft(0)((a, b) => 31 * a + b)

  /**
   * Output the BitCoin address in Base 58
   * @return The Base 58 representation of the BitCoin address
   */
  override def toString =
    BaseConvert.encode(toByteArray, 58)

  /**
   * Output the BitCoin address as a string in a specified radix (ie, base)
   * @param radix The base to output the BitCoin address to
   * @return A string representation of the BitCoin address
   */
  def toString(radix: Int) =
    BaseConvert.encode(toByteArray, radix)
}

object BitCoinAddress {

  /**
    * Convert a public key to a BitCoin address
    * @param publicKey The public key to compute the BitCoin address for
    * @return A BitCoin address corresponding to the specified public key
    */
  def apply(publicKey: PublicKey): BitCoinAddress = {
    val version: Byte = 0x00
    val hash = HashUtil.ripemd160(
        HashUtil.sha256(publicKey.toByteArray(compressed = false)))
    val checksum =
      HashUtil.sha256(HashUtil.sha256(Array[Byte](version) ++ hash)).take(4)
    new BitCoinAddress(version, hash, checksum)
  }

  /**
    * Get the BitCoin Address of a public key corresponding to a private key
    * @param privateKey A Private Key on Secp256k1
    * @return A BitCoin address corresponding to the public key of the specified private key
    */
  def apply(privateKey: PrivateKey): BitCoinAddress =
    apply(privateKey.publicKey)

  /**
    * Convert a string to a BitCoin address
    * @param input A BitCoin address in base 58
    * @return A BitCoin address, provided the string had a valid checksum
    */
  def apply(input: String): BitCoinAddress = apply(input, radix = 58)

  /**
    * Convert a string with specified radix to a BitCoin address
    * @param input A BitCoin address represented as a string
    * @param radix The radix (ie, base) of the string representation
    * @return A BitCoin address corresponding to the input string
    */
  def apply(input: String, radix: Int): BitCoinAddress =
    try apply(BaseConvert.decode(input, radix)) catch {
      case ex: IllegalArgumentException =>
        throw new SecurityException(ex.getMessage)
    }

  /**
    * Convert a byte sequence to a BitCoin address
    * @param data A BitCoin address represented as a byte sequence
    * @return A BitCoin address corresponding to the input byte sequence
    */
  def apply(data: Seq[Byte]): BitCoinAddress = {
    if (data.length != 25)
      throw new SecurityException(
          "Valid BitCoin addresses have 25 bytes, input has: " + data.length)
    val version = data.head
    val hash = data.drop(1).dropRight(4)
    val checksum = data.takeRight(4)
    new BitCoinAddress(version, hash, checksum)
  }
}
