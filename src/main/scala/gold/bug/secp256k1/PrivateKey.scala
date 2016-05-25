package gold.bug.secp256k1

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.{MessageDigest, SecureRandom}

import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.asn1.{ASN1Integer, DERSequenceGenerator}
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters, ECPrivateKeyParameters}
import org.spongycastle.crypto.signers.ECDSASigner

class PrivateKey(p: BigInteger) {
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

  private val key = new ECPrivateKeyParameters(p, curve)

  // TODO: RFC 6979? https://tools.ietf.org/html/rfc6979
  def sign(input : Array[Byte]): String = {
    assert (input.length * 8 <= curve.getN.bitLength,
      "Input cannot exceed curve modulus in bytes")
    val signatures = {
      val signer = new ECDSASigner()
      signer.init(true, key)
      signer.generateSignature(input)
    }
    val bos = new ByteArrayOutputStream()
    val s = new DERSequenceGenerator(bos)
    try {
      s.addObject(new ASN1Integer(signatures(0)))
      s.addObject(new ASN1Integer(signatures(1)))
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
   * Sign a string ; first takes a SHA256 hash of the string before signing (assumes UTF-8 encoding)
   * @param data A UTF-8 string
   * @return
   */
  def sign(data: String): String = {
    sign(MessageDigest.getInstance("SHA-256").digest(data.getBytes("UTF-8")))
  }

  def getPublicKey: PublicKey = {
    new PublicKey(curve.getG.multiply(p).normalize)
  }



  override def toString = p.toString(16)

  //noinspection ComparingUnrelatedTypes
  def canEqual(other: Any): Boolean = other.isInstanceOf[PrivateKey]

  override def equals(other: Any): Boolean = other match {
    case that: PrivateKey =>
      (that canEqual this) &&
        this.curve.getCurve == that.curve.getCurve &&
        this.curve.getG == that.curve.getG &&
        this.curve.getN == that.curve.getN &&
        this.curve.getH == that.curve.getH &&
        p == that.key.getD
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