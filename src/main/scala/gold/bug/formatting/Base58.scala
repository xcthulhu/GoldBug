package gold.bug.formatting

import java.math.BigInteger
object Base58 {

  private val bigFiftyEight = BigInteger.valueOf(58L)
  private val alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  private val characterToIntegerMap = alphabet.zipWithIndex.toMap
  private val characterToBigInteger =
    (characterToIntegerMap apply _) andThen (BigInteger.valueOf(_))

  /**
    * Encode a sequence of bytes as a Base58 string
    * @param input A sequence of bytes to be Base58 encoded
    * @return A Base58 output string
    */
  def toBase58String(input: Seq[Byte]): String = {
    def reversedBase58DigitStream(n: BigInteger): Stream[Char] = n match {
      case BigInteger.ZERO => Stream.empty
      case _ =>
        val Array(quotient, remainder) = n.divideAndRemainder(bigFiftyEight)
        alphabet.charAt(remainder.intValue) #:: reversedBase58DigitStream(
            quotient)
    }
    (reversedBase58DigitStream(new BigInteger(1, input.toArray)) ++
        input.takeWhile(_ == 0).map(Function.const('1'))).reverse.mkString
  }

  /**
    * Decode a Base58 representation of a sequence of bytes
    * @param input Base58 encoded data as a string
    * @return The decoded data
    */
  def decode(input: String): Array[Byte] = {
    Array.fill[Byte](input.takeWhile(_ == '1').length)(0) ++
    input
      .dropWhile(_ == '1')
      .map(characterToBigInteger)
      .foldLeft(BigInteger.ZERO)(_.multiply(bigFiftyEight).add(_))
      .toByteArray
      .dropWhile(_ == 0)
  }
}
