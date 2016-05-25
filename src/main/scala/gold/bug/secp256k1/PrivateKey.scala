package gold.bug.secp256k1

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom

import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.asn1.{ASN1Integer, DERSequenceGenerator}
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters, ECPrivateKeyParameters}
import org.spongycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}

class PrivateKey(D: BigInteger) {
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

  private val key = new ECPrivateKeyParameters(D, curve)

  /**
   * Sign a string ; first takes a SHA256 hash of the string before signing (assumes UTF-8 encoding)
   * @param data A UTF-8 string
   * @return
   */
  def sign(data: String): String = {
    sign(data.getBytes("UTF-8"))
  }

  def sign(input : Array[Byte]): String = {
    val signature = {
      // Generate an RFC 6979 compliant signature
      // See:
      //  - https://tools.ietf.org/html/rfc6979
      //  - https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/DeterministicDSATest.java#L27
      val digest = new SHA256Digest()
      val signer = new ECDSASigner(new HMacDSAKCalculator(digest))
      val message = new Array[Byte](digest.getDigestSize)
      digest.update(input, 0, input.length)
      digest.doFinal(message, 0)
      signer.init(true, key)
      signer.generateSignature(message)
    }
    val bos = new ByteArrayOutputStream()
    val s = new DERSequenceGenerator(bos)
    try {
      s.addObject(new ASN1Integer(signature(0)))
      s.addObject(new ASN1Integer(signature(1)))
    }
    finally {
      s.close()
    }
    val builder = new StringBuilder()
    for (byte <- bos.toByteArray)
      builder.append("%02x".format(byte & 0xff))
    builder.toString()
  }

  /**
   * Get the public key that corresponds to this private key
   * @return This private key's corresponding public key
   */
  def getPublicKey: PublicKey = {
    new PublicKey(curve.getG.multiply(D).normalize)
  }

  /**
   * Output the hex corresponding to this private key
   * @return
   */
  override def toString = D.toString(16)

  //noinspection ComparingUnrelatedTypes
  def canEqual(other: Any): Boolean = other.isInstanceOf[PrivateKey]

  override def equals(other: Any): Boolean = other match {
    case that: PrivateKey =>
      (that canEqual this) &&
        this.curve.getCurve == that.curve.getCurve &&
        this.curve.getG == that.curve.getG &&
        this.curve.getN == that.curve.getN &&
        this.curve.getH == that.curve.getH &&
        D == that.key.getD
    case _ => false
  }

  override def hashCode(): Int = {
    val state = Seq(curve, key)
    state.map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
  }
}

object PrivateKey {
  // TODO: DRY, make more abstract perhaps
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

  /**
   * Construct a private key from a hexadecimal string
   * @param input A hexadecimal string
   * @return A private key with exponent D corresponding to the input
   */
  def fromString(input : String) : PrivateKey = {
    new PrivateKey(new BigInteger(input, 16))
  }

  /**
   * Generate a new random private key.  Uses java.security.SecureRandom
   * @return A random private key
   */
  def generateRandom : PrivateKey = {
    val generator = new ECKeyPairGenerator()
    generator.init(new ECKeyGenerationParameters(curve, new SecureRandom()))
    new PrivateKey(generator.generateKeyPair.getPrivate.asInstanceOf[ECPrivateKeyParameters].getD)
  }
}