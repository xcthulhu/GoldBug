package gold.bug.addresses

import gold.bug.HashUtil
import gold.bug.formatting.BaseConvert

/**
  * Following EIP 55, see:
  * - https://github.com/ethereum/EIPs/issues/55
  * - https://github.com/ethereum/go-ethereum/blob/aa9fff3e68b1def0a9a22009c233150bf9ba481f/jsre/ethereum_js.go#L2288-L2375
  */
class EthereumAddress(_address: String) {
  private val address = _address.replaceFirst("^0[x,X]", "")
  if (!address.matches("[0-9a-fA-F]{40}"))
    throw new SecurityException("Address must be a 20 byte hexadecimal string")
  if (!(address.toLowerCase == address) && !(address.toUpperCase == address) &&
      !(toString.replaceFirst("^0[x,X]", "") == address))
    throw new SecurityException(
        "Ethereum address does not have a valid checksum")

  /**
    * Output the Ethereum address as a byte array (effectively removing the checksum)
    * @return A byte array encoding the Ethereum address, which has no checksum information associated with it
    */
  def toByteArray = BaseConvert.decode(address, 16)

  /**
    * Output the check summed case sensitive hexadecimal Ethereum address using the EIP 55 algorithm 
    * @return A case sensitive hexadecimal checksummed Ethereum address
    */
  override def toString =
    "0x" ++ (address.toLowerCase zip
        BaseConvert
          .encode(HashUtil.keccak256(address.toLowerCase), 16)
          .map(Character.digit(_, 16))).map {
      case (c, b) => if (b > 7) c.toUpper else c
    }.mkString

  //noinspection ComparingUnrelatedTypes
  def canEqual(other: Any): Boolean = other.isInstanceOf[EthereumAddress]

  override def equals(other: Any): Boolean = other match {
    case that: EthereumAddress =>
      (that canEqual this) && toString == that.toString
    case _ => false
  }

  override def hashCode(): Int =
    Seq(toString).map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
}

object EthereumAddress {

//  /**
//    * Convert a public key to a BitCoin address
//    * @param publicKey The public key to compute the BitCoin address for
//    * @return A BitCoin address corresponding to the specified public key
//    */
//  def apply(publicKey: PublicKey): EthereumAddress = {
//    val version: Byte = 0x00
//    val hash = Hashers.ripemd160(
//        Hashers.sha256(publicKey.toByteArray(compressed = false)))
//    val checksum =
//      Hashers.sha256(Hashers.sha256(Array[Byte](version) ++ hash)).take(4)
//    new EthereumAddress(version, hash, checksum)
//  }

  /**
    * Convert a string with specified radix to an Ethereum address
    * @param input An Ethereum address represented as a string
    * @param radix The radix (ie, base) of the string representation (defaults to 16)
    * @return An Ethereum address corresponding to the input string
    */
  def apply(input: String, radix: Int = 16): EthereumAddress =
    radix match {
      case 16 => new EthereumAddress(input)
      case _ =>
        try new EthereumAddress(BaseConvert.convert(input, radix, 16)) catch {
          case ex: IllegalArgumentException =>
            throw new SecurityException(ex.getMessage)
        }
    }

  /**
    * Convert a byte sequence to an Ethereum address
    * @param data A BitCoin address represented as a string
    * @return A BitCoin address corresponding to the input byte sequence
    */
  def apply(data: Seq[Byte]): EthereumAddress =
    new EthereumAddress(BaseConvert.encode(data, 16))
}
