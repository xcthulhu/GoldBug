package gold.bug

import java.security.MessageDigest

import org.spongycastle.crypto.digests.RIPEMD160Digest
import org.spongycastle.jcajce.provider.digest.Keccak

object HashUtil {

  /**
    * Compute the SHA256 hash of a UTF-8 string
    * @param data A UTF-8 encoded string
    * @return A byte array of the hashed data
    */
  def sha256(data: String): Array[Byte] =
    sha256(data.getBytes("UTF-8"))

  /**
    * Compute the SHA256 hash of a byte array
    * @param data A byte array of data to be hashed
    * @return A byte array of the hashed data
    */
  def sha256(data: Seq[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(data.toArray)

  /**
    * Compute the RIPEMD160 hash of a byte array
    * @param data A byte sequence to be hashed
    * @return A byte array of the hashed data
    */
  def ripemd160(data: Seq[Byte]): Array[Byte] = {
    val messageDigest = new RIPEMD160Digest
    messageDigest.update(data.toArray, 0, data.length)
    val out = Array.fill[Byte](messageDigest.getDigestSize)(0)
    messageDigest.doFinal(out, 0)
    out
  }

  /**
    * Compute a Keccak-256 hash of a UTF-8 encoded string
    *
    * Note: In Ethereum source code this is often erroneously referred to as SHA3,
    *  however the NIST specification for SHA3 differs from the algorithm used by Ethereum.
    *  
    *  See:
    *    - https://media.consensys.net/2016/01/12/are-you-really-using-sha-3-or-old-code/
    *    - http://ethereum.stackexchange.com/a/554
    *
    * @param data A UTF-8 encoded string to be hashed
    * @return A byte array of the hashed data
    */
  def keccak256(data: String): Array[Byte] =
    keccak256(data.getBytes("UTF-8"))

  /**
    * Compute a Keccak-256 hash of a sequence of bytes
    * 
    * Note: In Ethereum source code this is often erroneously referred to as SHA3,
    *  however the NIST specification for SHA3 differs from the algorithm used by Ethereum.
    *  
    *  See:
    *    - https://media.consensys.net/2016/01/12/are-you-really-using-sha-3-or-old-code/
    *    - http://ethereum.stackexchange.com/a/554
    *  
    * @param data A byte sequence to be hashed
    * @return A byte array of the hashed data
    */
  def keccak256(data: Seq[Byte]): Array[Byte] =
    (new Keccak.Digest256).digest(data.toArray)
}
