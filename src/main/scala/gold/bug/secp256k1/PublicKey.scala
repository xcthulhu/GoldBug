package gold.bug.secp256k1

import java.math.BigInteger
import java.security.MessageDigest

import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.asn1._
import org.spongycastle.crypto.params.{ECDomainParameters, ECPublicKeyParameters}
import org.spongycastle.crypto.signers.ECDSASigner
import org.spongycastle.math.ec.ECPoint


class PublicKey (point: ECPoint) {
  // TODO: DRY, make more abstract perhaps
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

  private val key = new ECPublicKeyParameters(point, curve)

  /**
   * Convert to a X.509 encoded string
   * @param compressed Whether to output a compressed key or not
   * @return A X.509 encoded string
   */
  def toString(compressed: Boolean = true): String = {
    val builder = new StringBuilder()
    def zeroPadLeft(input: String) : Unit = {
      assert (input.length * 4 <= curve.getN.bitLength,
        "Input cannot have more bits than the curve modulus")
      if(input.length * 4 < curve.getN.bitLength)
        for( _ <- 1 to (curve.getN.bitLength / 4 - input.length))
          builder.append("0")
      builder.append(input)
    }
    val normalizedPoint = point.normalize

    if (compressed) {
      builder.append(if (normalizedPoint.getYCoord.toBigInteger.testBit(0)) "03" else "02")
      zeroPadLeft(normalizedPoint.getXCoord.toBigInteger.toString(16))
    }  else {
      builder.append("04")
      zeroPadLeft(normalizedPoint.getXCoord.toBigInteger.toString(16))
      zeroPadLeft(normalizedPoint.getYCoord.toBigInteger.toString(16))
    }
    builder.toString()
  }

  override def toString = toString()

  /**
   * Verify a signature against this public key
   * @param input A hex string representing the input to be verified
   * @param signature The ECDSA signature bytes as a hex string
   * @return Whether the signature is valid
   */
  def verify(input : String, signature: String): Boolean = {
    verify(input, new BigInteger(signature, 16).toByteArray)
  }

  def verify(input : Array[Byte], signature : Array[Byte]): Boolean = {
    val verifier = new ECDSASigner()
    verifier.init(false, key)
    val decoder = new ASN1InputStream(signature)
    try {
      val sequence = decoder.readObject().asInstanceOf[DLSequence]
      val r : BigInteger = sequence.getObjectAt(0).asInstanceOf[ASN1Integer].getValue
      val s : BigInteger = sequence.getObjectAt(1).asInstanceOf[ASN1Integer].getValue
      verifier.verifySignature(input, r, s)
    } finally {
      decoder.close()
    }
  }

  def verify(input : Array[Byte], signature: String): Boolean = {
    verify(input, new BigInteger(signature, 16).toByteArray)
  }

  def verify(input : String, signature : Array[Byte]): Boolean = {
    verify(MessageDigest.getInstance("SHA-256").digest(input.getBytes("UTF-8")), signature)
  }

  //noinspection ComparingUnrelatedTypes
  def canEqual(other: Any): Boolean = other.isInstanceOf[PublicKey]

  override def equals(other: Any): Boolean = other match {
    case that: PublicKey =>
      (that canEqual this) && {
        val thisNormalizedPoint = point.normalize
        val thatNormalizedPoint = that.key.getQ.normalize
        thisNormalizedPoint.getXCoord == thatNormalizedPoint.getXCoord &&
          thisNormalizedPoint.getYCoord == thatNormalizedPoint.getYCoord
      } &&
        this.curve.getCurve == that.curve.getCurve &&
        this.curve.getG == that.curve.getG &&
        this.curve.getN == that.curve.getN &&
        this.curve.getH == that.curve.getH
    case _ => false
  }

  override def hashCode(): Int = {
    val state = Seq(curve, key)
    state.map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
  }
}

object PublicKey {
  // TODO: DRY, make more abstract perhaps
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

  /**
   * Construct a PublicKey from an X.509 encoded hexadecimal string
   * @param input An X.509 encoded hexadecimal string
   * @return
   */
  def fromString(input:String) : PublicKey = {
    new PublicKey(
      curve
        .getCurve
        .decodePoint(new BigInteger(input, 16).toByteArray)
        .normalize)
  }
}