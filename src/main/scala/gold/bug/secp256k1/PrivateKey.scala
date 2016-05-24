package gold.bug.secp256k1

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest

import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.asn1.{ASN1Integer, DERSequenceGenerator}
import org.spongycastle.crypto.params.{ECDomainParameters, ECPrivateKeyParameters}
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

  def sign(data: String): String = {
    sign(MessageDigest.getInstance("SHA-256").digest(data.getBytes("UTF-8")))
  }

  def getPublicKey: PublicKey = {
    new PublicKey(curve.getG.multiply(p).normalize)
  }

  override def toString = p.toString(16)
}

object PrivateKey {
  def fromString(input : String) : PrivateKey = {
    new PrivateKey(new BigInteger(input, 16))
  }
}