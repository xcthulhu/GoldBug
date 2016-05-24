package gold.bug.secp256k1

import java.math.BigInteger

import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.crypto.params.ECDomainParameters
import org.spongycastle.math.ec.ECPoint


class PublicKey (point: ECPoint) {
  // TODO: DRY, make more abstract perhaps
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

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
}

object PublicKey {
  // TODO: DRY, make more abstract perhaps
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  }

  def fromString(input:String) : PublicKey = {
    new PublicKey(
      curve
      .getCurve
      .decodePoint(new BigInteger(input, 16).toByteArray)
        .normalize)
  }
}