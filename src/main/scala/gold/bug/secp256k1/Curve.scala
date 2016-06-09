package gold.bug.secp256k1

/**
  * WARNING: Scala gets confused when you try to deserialize a byte array into a `BigInteger`,
  * so *always* use `java.math.BigInteger` to be maximally explicit - import java.math.BigInteger at your own risk!
  */
import java.io.ByteArrayOutputStream
import java.security.{MessageDigest, SecureRandom}
import java.util.Random

import org.spongycastle.asn1._
import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters, ECPrivateKeyParameters, ECPublicKeyParameters}
import org.spongycastle.crypto.signers.ECDSASigner
import org.spongycastle.math.ec.{ECAlgorithms, ECPoint}

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
    def sign(data: String, includeRecoveryByte: Boolean = false): String = {
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

    // TODO: Make this actually deterministic
    // https://github.com/vbuterin/pybitcointools/blob/8e8a33d7281c871950519e5f256ad08cf0d5df69/bitcoin/main.py#L493
    def deterministicGenerateK(hash: Array[Byte]): java.math.BigInteger = {
      val random: Random = new SecureRandom()
      new java.math.BigInteger(curve.getN.bitLength, random)
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
      * @param hash A byte array to be signed
      * @param includeRecoveryByte A boolean indicating whether a recovery byte should be included
      * @return A hex string containing the DER signature
      */
    def signHash(
        hash: Array[Byte], includeRecoveryByte: Boolean = true): String = {
      // Generate an RFC 6979 compliant signature
      // See:
      //  - https://tools.ietf.org/html/rfc6979
      //  - https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/DeterministicDSATest.java#L27
      val z: java.math.BigInteger = new java.math.BigInteger(1, hash)
      val k: java.math.BigInteger = deterministicGenerateK()
      val kp: ECPoint = curve.getG.multiply(k).normalize()
      val n: java.math.BigInteger = curve.getN
      val r: java.math.BigInteger = kp.getXCoord.toBigInteger.mod(n)
      val _s: java.math.BigInteger =
        k.modInverse(n).multiply(r.multiply(D).add(z)).mod(n)
      val s: java.math.BigInteger =
        if (_s.add(_s).compareTo(n) == -1) _s else n.subtract(_s)
      val builder = new StringBuilder()
      if (includeRecoveryByte) {
        val recoveryByte =
          0x1B +
          (if (kp.getYCoord.toBigInteger.testBit(0) ^ _s != s) 1 else 0) +
          (if (r.compareTo(n) == -1) 0 else 2)
        builder.append("%02x".format(recoveryByte & 0xff))
      }
      for (byte <- ecdsaDERBytes(r, s)) builder.append(
          "%02x".format(byte & 0xff))
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
      new PrivateKey(new java.math.BigInteger(input, 16))
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

  class PublicKey(point: ECPoint) {
    private val curve = self.curve

    private val key = new ECPublicKeyParameters(point.normalize, curve)

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
      verify(input, new java.math.BigInteger(signature, 16).toByteArray)
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
      verify(input, new java.math.BigInteger(signature, 16).toByteArray)
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
      val normalizedPoint = point.normalize

      if (compressed) {
        encodeXCoordinate(!normalizedPoint.getYCoord.toBigInteger.testBit(0),
                          normalizedPoint.getXCoord.toBigInteger)
      } else {
        val builder = new StringBuilder()
        builder.append("04")
        zeroPadLeft(
            builder, normalizedPoint.getXCoord.toBigInteger.toString(16))
        zeroPadLeft(
            builder, normalizedPoint.getYCoord.toBigInteger.toString(16))
        builder.toString()
      }
    }

    private def decodeECPoint(input: String): ECPoint = {
      curve.getCurve
        .decodePoint(new java.math.BigInteger(input, 16).toByteArray)
        .normalize
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
      recoverPublicKey(
          input, new java.math.BigInteger(signature, 16).toByteArray)
    }

    def recoverPublicKey(input: String, signature: Array[Byte]): PublicKey = {
      recoverPublicKey(input.getBytes("UTF-8"), signature)
    }

    def recoverPublicKey(input: Array[Byte], signature: String): PublicKey = {
      recoverPublicKey(
          input, new java.math.BigInteger(signature, 16).toByteArray)
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
