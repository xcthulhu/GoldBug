package gold.bug.secp256k1

/**
  * WARNING: Scala gets confused when you try to deserialize a byte array into a `BigInteger`,
  * so *always* use `java.math.BigInteger` to be maximally explicit - import java.math.BigInteger at your own risk!
  */
import java.io.ByteArrayOutputStream
import java.security.{MessageDigest, SecureRandom}

import org.spongycastle.asn1._
import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params._
import org.spongycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}
import org.spongycastle.math.ec.{ECAlgorithms, ECPoint}
import org.spongycastle.util.encoders.Hex

import scala.annotation.tailrec

// TODO: Parametrize with ECDomainParameters or something?
object Curve { self =>
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(
        params.getCurve, params.getG, params.getN, params.getH)
  }

  class PrivateKey(D: java.math.BigInteger) {
    private val curve = self.curve
    private val key = new ECPrivateKeyParameters(D, curve)

    /**
      * Sign a UTF-8 encoded string (first takes SHA256 hash of string)
      * @param data A UTF-8 string
      * @param includeRecoveryByte A boolean indicating whether a recovery byte should be included (defaults to true)
      * @return
      */
    def sign(data: String, includeRecoveryByte: Boolean = true): String = {
      sign(data.getBytes("UTF-8"), includeRecoveryByte)
    }

    /**
      * Sign a UTF-8 encoded string (first takes SHA256 hash of string)
      * @param data A UTF-8 string
      * @param includeRecoveryByte A boolean indicating whether a recovery byte should be included (defaults to true)
      * @return
      */
    def sign(data: Array[Byte], includeRecoveryByte: Boolean): String = {
      signHash(MessageDigest.getInstance("SHA-256").digest(data),
               includeRecoveryByte)
    }

    /**
      * Convert this private key to an array of bytes
      * @return An array of bytes, with the same number of bytes as the curve modulus
      */
    def toByteArray: Array[Byte] = {
      val bytes: Array[Byte] = D.toByteArray.dropWhile(z => z == 0x00.toByte)
      assert(bytes.length * 8 <= curve.getN.bitLength,
             "Private key cannot have more than " + curve.getN.bitLength +
             " bits (had " + bytes.length * 8 + ")")
      val curveBytes: Int = curve.getN.bitLength / 8
      assert(curveBytes * 8 == curve.getN.bitLength)
      if (bytes.length < curveBytes)
        Array.fill[Byte](curveBytes - bytes.length)(0x00) ++ bytes
      else bytes
    }

    /**
      * Generate random numbers following the specification in RFC 6979, Section 3.2
      * See: https://tools.ietf.org/html/rfc6979#section-3.2
      * @param messageHash The data to be used in generating the signature
      * @return A deterministic random number generator, where the first generated value is precisely the number specified in RFC 6979
      */
    def getDeterministicKGenerator(
        messageHash: Array[Byte]): HMacDSAKCalculator = {
      val curveBytes: Int = curve.getN.bitLength / 8
      assert(curveBytes * 8 == curve.getN.bitLength,
             "Curve is not an even number of bytes in length")
      assert(
          curveBytes == messageHash.length,
          "Hashed input is not the same length as the number of bytes in the curve")
      val kCalculator = new HMacDSAKCalculator(new SHA256Digest)
      kCalculator.init(curve.getN, key.getD, messageHash)
      kCalculator
    }

    private def ecdsaDERBytes(
        r: java.math.BigInteger, s: java.math.BigInteger): Array[Byte] = {
      val bos = new ByteArrayOutputStream()
      val sequenceGenerator = new DERSequenceGenerator(bos)
      try {
        sequenceGenerator.addObject(new ASN1Integer(r))
        sequenceGenerator.addObject(new ASN1Integer(s))
      } finally {
        sequenceGenerator.close()
      }
      bos.toByteArray
    }

    /**
      * Sign a byte array representing hashed data
      * @param messageHash A byte array to be signed
      * @param includeRecoveryByte A boolean indicating whether a recovery byte should be included
      * @return A hex string containing the DER signature
      */
    def signHash(messageHash: Array[Byte],
                 includeRecoveryByte: Boolean = true): String = {
      // Generate an RFC 6979 compliant signature
      // See: https://tools.ietf.org/html/rfc6979
      val curveBytes: Int = curve.getN.bitLength / 8
      assert(curveBytes * 8 == curve.getN.bitLength,
             "Curve is not an even number of bytes in length")
      assert(
          curveBytes == messageHash.length,
          "Hashed input is not the same length as the number of bytes in the curve")
      val z = new java.math.BigInteger(1, messageHash)
      val n = curve.getN
      val kCalculator = getDeterministicKGenerator(messageHash)
      class Parameters(val recoveryByte: Byte,
                       val r: java.math.BigInteger,
                       val s: java.math.BigInteger)
      @tailrec def getParameters: Parameters = {
        val k = kCalculator.nextK
        val kp = curve.getG.multiply(k).normalize
        val r = kp.getXCoord.toBigInteger.mod(n)
        val _s = k.modInverse(n).multiply(r.multiply(D).add(z)).mod(n)
        val s = if (_s.add(_s).compareTo(n) == -1) _s else n.subtract(_s)
        val recoveryByte =
          (0x1B + (if (kp.getYCoord.toBigInteger.testBit(0) ^ _s != s) 1
                   else 0) + (if (r.compareTo(n) == -1) 0 else 2)).toByte
        if (s.equals(java.math.BigInteger.ZERO) ||
            r.equals(java.math.BigInteger.ZERO)) getParameters
        else new Parameters(recoveryByte, r, s)
      }
      val parameters = getParameters
      Hex.toHexString(
          (if (includeRecoveryByte) Array(parameters.recoveryByte)
           else Array.empty) ++ ecdsaDERBytes(parameters.r, parameters.s))
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
      * Construct a random new private key
      * @return A random new private key
      */
    def apply(): PrivateKey = {
      PrivateKey.generateRandom
    }

    /**
      * Construct a private key from a hexadecimal string
      * @param input A hexadecimal string
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: String): PrivateKey = {
      new PrivateKey(new java.math.BigInteger(1, Hex.decode(input)))
    }

    /**
      * Construct a private key from a byte array
      * @param input A byte array
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: Array[Byte]): PrivateKey = {
      new PrivateKey(new java.math.BigInteger(1, input))
    }

    /**
      * Construct a private key from a string with specified base
      * @param input A string with the specified base
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: String, base: Int): PrivateKey = {
      new PrivateKey(new java.math.BigInteger(input, base))
    }

    /**
      * Construct a private key from a java.math.BigInteger
      * @param input A hexadecimal string
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: java.math.BigInteger): PrivateKey = {
      new PrivateKey(input)
    }

    /**
      * Copy constructor (identity function, since private keys are immutable)
      * @param input A private key
      * @return That same private key
      */
    def apply(input: PrivateKey): PrivateKey = input

    /**
      * Generate a new random private key; Uses java.security.SecureRandom
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

  class PublicKey(_point: ECPoint) {
    private val curve = self.curve
    private val point = _point.normalize
    private val key = new ECPublicKeyParameters(point, curve)

    /**
      * Convert to a X.509 encoded string
      * @param compressed Boolean whether to output a compressed key or not (defaults to true so the output is compressed)
      * @return A X.509 encoded string
      */
    def toString(compressed: Boolean = true): String = {
      PublicKey.encodeECPoint(key.getQ, compressed)
    }

    override def toString = toString()

    private def verifyECDSA(
        hash: Array[Byte], signature: Array[Byte]): Boolean = {
      val decoder = new ASN1InputStream(signature)
      try {
        val sequence = decoder.readObject().asInstanceOf[DLSequence]
        val r = sequence.getObjectAt(0).asInstanceOf[ASN1Integer].getValue
        val s = sequence.getObjectAt(1).asInstanceOf[ASN1Integer].getValue
        val verifier = new ECDSASigner()
        verifier.init(false, key)
        verifier.verifySignature(hash, r, s)
      } finally {
        decoder.close()
      }
    }

    /**
      * Verify a signature against this public key
      * @param hash Bytes representing the hashed input to be verified
      * @param signature The ECDSA signature bytes
      * @return Boolean whether the signature is valid
      */
    def verifyHash(hash: Array[Byte], signature: Array[Byte]): Boolean = {
      assert(hash.length * 8 == curve.getN.bitLength,
             "Hash must have " + curve.getN.bitLength + "bits (had " +
             hash.length * 8 + " bits)")
      signature(0) match {
        case 0x1B | 0x1C | 0x1D | 0x1E =>
          this == PublicKey.recoverPublicKeyFromHash(hash, signature)
        case 0x30 =>
          verifyECDSA(hash, signature)
        case _ => throw new RuntimeException("Unknown signature format")
      }
    }

    /**
      * Verify a signature against this public key
      * @param input Bytes to be hashed and then verified
      * @param signature The ECDSA signature bytes
      * @return Boolean whether the signature is valid
      */
    def verify(input: Array[Byte], signature: Array[Byte]): Boolean = {
      verifyHash(MessageDigest.getInstance("SHA-256").digest(input), signature)
    }

    /**
      * Verify a signature against this public key
      * @param input Bytes to be hashed and then verified
      * @param signature The ECDSA signature bytes as a hex string
      * @return Boolean whether the signature is valid
      */
    def verify(input: Array[Byte], signature: String): Boolean = {
      verify(input, Hex.decode(signature))
    }

    /**
      * Verify a signature against this public key
      * @param input UTF-8 encoded string to be hashed and then verified
      * @param signature The ECDSA signature bytes
      * @return Boolean whether the signature is valid
      */
    def verify(input: String, signature: Array[Byte]): Boolean = {
      verify(input.getBytes("UTF-8"), signature)
    }

    /**
      * Verify a signature against this public key
      * @param input UTF-8 encoded string to be hashed and then verified
      * @param signature The ECDSA signature bytes as a hex string
      * @return Boolean whether the signature is valid
      */
    def verify(input: String, signature: String): Boolean = {
      verify(input, Hex.decode(signature))
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

    private def zeroPadLeft(builder: StringBuilder, input: String): Unit = {
      assert(input.length * 4 <= curve.getN.bitLength,
             "Input:\n\n" + input + "\n\ncannot have more than " +
             curve.getN.bitLength + "bits, the curve modulus (had " +
             input.length * 4 + " bits)")
      if (input.length * 4 < curve.getN.bitLength)
        for (_ <- 1 to (curve.getN.bitLength / 4 - input.length)) builder
          .append("0")
      builder.append(input)
    }

    private def encodeXCoordinate(
        yEven: Boolean, xCoordinate: java.math.BigInteger): String = {
      val builder = new StringBuilder()
      builder.append(if (yEven) "02" else "03")
      zeroPadLeft(builder, xCoordinate.toString(16))
      builder.toString()
    }

    private def encodeECPoint(
        point: ECPoint, compressed: Boolean = true): String = {
      if (compressed) {
        encodeXCoordinate(!point.getYCoord.toBigInteger.testBit(0),
                          point.getXCoord.toBigInteger)
      } else {
        val builder = new StringBuilder()
        builder.append("04")
        zeroPadLeft(builder, point.getXCoord.toBigInteger.toString(16))
        zeroPadLeft(builder, point.getYCoord.toBigInteger.toString(16))
        builder.toString()
      }
    }

    private def decodeECPoint(input: String): ECPoint = {
      curve.getCurve.decodePoint(Hex.decode(input)).normalize
    }

    /**
      * Construct a PublicKey from an X.509 encoded hexadecimal string
      * @param input An X.509 encoded hexadecimal string
      * @return The corresponding public key
      */
    def apply(input: String): PublicKey = {
      new PublicKey(decodeECPoint(input))
    }

    /**
      * Copy constructor (identity function, since public keys are immutable)
      * @param input A public key
      * @return The corresponding public key
      */
    def apply(input: PublicKey): PublicKey = input

    /**
      * Construct a PublicKey from a private key
      * @param input A private key
      * @return The corresponding public key
      */
    def apply(input: PrivateKey): PublicKey = input.getPublicKey

    /**
      * Construct a public key from an elliptic curve point
      * @param input An elliptic curve point
      * @return The corresponding public key
      */
    def apply(input: ECPoint): PublicKey = {
      val publicKey = new PublicKey(input.normalize())
      assert(publicKey == PublicKey.apply(publicKey.toString()),
             "Elliptic curve point is not valid")
      publicKey
    }

    /**
      * Given the components of a signature and a selector value, recover and return the public key
      * that generated the signature according to the algorithm in SEC1v2 section 4.1.6
      *
      * @param hash The hash signed
      * @param recoveryByte One of 0x1B, 0x1C, 1x1D, or 0x1E
      * @param r The R component of the ECDSA signature
      * @param s The S component of the ECDSA signature
      * @return The recovered public key
      */
    def ecrecover(hash: Array[Byte],
                  recoveryByte: Byte,
                  r: java.math.BigInteger,
                  s: java.math.BigInteger): PublicKey = {
      assert(hash.length * 8 == curve.getN.bitLength,
             "Hash must have " + curve.getN.bitLength + "bits (had " +
             hash.length * 8 + " bits)")
      assert(0x1B <= recoveryByte && recoveryByte <= 0x1E,
             "Recovery byte must be 0x1B, 0x1C, 0x1D, or 0x1E")
      assert(r.toByteArray.length * 4 <= curve.getN.bitLength,
             "R component out of range")
      assert(s.toByteArray.length * 4 <= curve.getN.bitLength,
             "S component out of range")
      val yEven = ((recoveryByte - 0x1B) & 1) == 0
      val isSecondKey = ((recoveryByte - 0x1B) >> 1) == 1
      val n = curve.getN
      val p = curve.getCurve.getField.getCharacteristic
      if (isSecondKey)
        assert(
            r.compareTo(p.mod(n)) >= 0, "Unable to find second key candidate")
      // 1.1. Let x = r + jn.
      val encodedPoint = encodeXCoordinate(
          yEven, if (isSecondKey) r.add(n) else r)
      val R = decodeECPoint(encodedPoint)
      val eInv = n.subtract(new java.math.BigInteger(1, hash))
      val rInv = r.modInverse(n)
      // 1.6.1 Compute Q = r^-1 (sR + -eG)
      new PublicKey(
          ECAlgorithms
            .sumOfTwoMultiplies(curve.getG, eInv, R, s)
            .multiply(rInv)
            .normalize)
    }

    def recoverPublicKey(input: String, signature: String): PublicKey = {
      recoverPublicKey(input, Hex.decode(signature))
    }

    def recoverPublicKey(input: String, signature: Array[Byte]): PublicKey = {
      recoverPublicKey(input.getBytes("UTF-8"), signature)
    }

    def recoverPublicKey(input: Array[Byte], signature: String): PublicKey = {
      recoverPublicKey(input, Hex.decode(signature))
    }

    def recoverPublicKey(
        input: Array[Byte], signature: Array[Byte]): PublicKey = {
      recoverPublicKeyFromHash(
          MessageDigest.getInstance("SHA-256").digest(input), signature)
    }

    def recoverPublicKeyFromHash(
        hash: Array[Byte], signature: Array[Byte]): PublicKey = {
      assert(hash.length * 8 == curve.getN.bitLength,
             "Hash must have " + curve.getN.bitLength + "bits (had " +
             hash.length * 8 + " bits)")
      val decoder = new ASN1InputStream(signature.slice(1, signature.length))
      try {
        val recoveryByte = signature(0)
        val sequence = decoder.readObject().asInstanceOf[DLSequence]
        val r: java.math.BigInteger =
          sequence.getObjectAt(0).asInstanceOf[ASN1Integer].getValue
        val s: java.math.BigInteger =
          sequence.getObjectAt(1).asInstanceOf[ASN1Integer].getValue
        ecrecover(hash, recoveryByte, r, s)
      } finally {
        decoder.close()
      }
    }
  }
}
