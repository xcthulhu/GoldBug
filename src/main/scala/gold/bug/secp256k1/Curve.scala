package gold.bug.secp256k1

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.{MessageDigest, SecureRandom}

import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.asn1.{ASN1InputStream, ASN1Integer, DERSequenceGenerator, DLSequence}
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters, ECPrivateKeyParameters, ECPublicKeyParameters}
import org.spongycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}
import org.spongycastle.math.ec.ECPoint

// TODO: Parametrize with ECDomainParameters or something?
object Curve { self =>
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(
        params.getCurve, params.getG, params.getN, params.getH)
  }

  class PrivateKey(D: BigInteger) {
    private val curve = self.curve
    private val key = new ECPrivateKeyParameters(D, curve)

    /**
      * Sign a string ; first takes a SHA256 hash of the string before signing (assumes UTF-8 encoding)
      * @param data A UTF-8 string
      * @return
      */
    def sign(data: String): String = {
      sign(data.getBytes("UTF-8"))
    }

    def sign(input: Array[Byte]): String = {
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
      } finally {
        s.close()
      }
      val builder = new StringBuilder()
      for (byte <- bos.toByteArray) builder.append("%02x".format(byte & 0xff))
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
        (that canEqual this) && this.curve.getCurve == that.curve.getCurve &&
        this.curve.getG == that.curve.getG &&
        this.curve.getN == that.curve.getN &&
        this.curve.getH == that.curve.getH && D == that.key.getD
      case _ => false
    }

    override def hashCode(): Int = {
      val state = Seq(curve, key)
      state.map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
    }
  }

  object PrivateKey {
    private val curve = self.curve

    /**
      * Construct a private key from a hexadecimal string
      * @param input A hexadecimal string
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: String): PrivateKey = {
      new PrivateKey(new BigInteger(input, 16))
    }

    def apply(input: PrivateKey): PrivateKey = input

    /**
      * Generate a new random private key.  Uses java.security.SecureRandom
      * @return A random private key
      */
    def generateRandom: PrivateKey = {
      val generator = new ECKeyPairGenerator()
      generator.init(new ECKeyGenerationParameters(curve, new SecureRandom()))
      new PrivateKey(
          generator.generateKeyPair.getPrivate
            .asInstanceOf[ECPrivateKeyParameters]
            .getD)
    }
  }

  class PublicKey(point: ECPoint) {
    private val curve = self.curve

    private val key = new ECPublicKeyParameters(point.normalize, curve)
    private val verifier = {
      val verifier = new ECDSASigner()
      verifier.init(false, key)
      verifier
    }

    /**
      * Convert to a X.509 encoded string
      * @param compressed Whether to output a compressed key or not
      * @return A X.509 encoded string
      */
    def toString(compressed: Boolean = true): String = {
      val builder = new StringBuilder()
      def zeroPadLeft(input: String): Unit = {
        assert(input.length * 4 <= curve.getN.bitLength,
               "Input cannot have more bits than the curve modulus")
        if (input.length * 4 < curve.getN.bitLength)
          for (_ <- 1 to (curve.getN.bitLength / 4 - input.length)) builder
            .append("0")
        builder.append(input)
      }
      val normalizedPoint = key.getQ.normalize

      if (compressed) {
        builder.append(
            if (normalizedPoint.getYCoord.toBigInteger.testBit(0)) "03"
            else "02")
        zeroPadLeft(normalizedPoint.getXCoord.toBigInteger.toString(16))
      } else {
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
    def verify(input: String, signature: String): Boolean = {
      verify(input, new BigInteger(signature, 16).toByteArray)
    }

    def verify(input: Array[Byte], signature: Array[Byte]): Boolean = {
      val decoder = new ASN1InputStream(signature)
      try {
        val sequence = decoder.readObject().asInstanceOf[DLSequence]
        val r: BigInteger =
          sequence.getObjectAt(0).asInstanceOf[ASN1Integer].getValue
        val s: BigInteger =
          sequence.getObjectAt(1).asInstanceOf[ASN1Integer].getValue
        verifier.verifySignature(input, r, s)
      } finally {
        decoder.close()
      }
    }

    def verify(input: Array[Byte], signature: String): Boolean = {
      verify(input, new BigInteger(signature, 16).toByteArray)
    }

    def verify(input: String, signature: Array[Byte]): Boolean = {
      verify(
          MessageDigest.getInstance("SHA-256").digest(input.getBytes("UTF-8")),
          signature)
    }

    //noinspection ComparingUnrelatedTypes
    def canEqual(other: Any): Boolean = other.isInstanceOf[PublicKey]

    override def equals(other: Any): Boolean = other match {
      case that: PublicKey =>
        (that canEqual this) && {
          val thisNormalizedPoint = key.getQ.normalize
          val thatNormalizedPoint = that.key.getQ.normalize
          thisNormalizedPoint.getXCoord == thatNormalizedPoint.getXCoord &&
          thisNormalizedPoint.getYCoord == thatNormalizedPoint.getYCoord
        } && this.curve.getCurve == that.curve.getCurve &&
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
    private val curve = self.curve

    /**
      * Construct a PublicKey from an X.509 encoded hexadecimal string
      * @param input An X.509 encoded hexadecimal string
      * @return
      */
    def apply(input: String): PublicKey = {
      new PublicKey(
          curve.getCurve
            .decodePoint(new BigInteger(input, 16).toByteArray)
            .normalize)
    }

    def apply(input: PublicKey): PublicKey = input

    def apply(input: PrivateKey): PublicKey = input.getPublicKey
  }
}
