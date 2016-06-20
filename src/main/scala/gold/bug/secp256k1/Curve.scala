package gold.bug.secp256k1

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.{MessageDigest, SecureRandom}

import gold.bug.formatting.BaseConvert
import org.spongycastle.asn1._
import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params._
import org.spongycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}
import org.spongycastle.math.ec.{ECAlgorithms, ECPoint}

// TODO: Parametrize with ECDomainParameters or something?
object Curve {
  private val curve = {
    val params = SECNamedCurves.getByName("secp256k1")
    new ECDomainParameters(
        params.getCurve, params.getG, params.getN, params.getH)
  }
  private val curveBytes: Int = curve.getN.bitLength / 8
  assert(curveBytes * 8 == curve.getN.bitLength)
  private val defaultBase: Int = 16

  private def sha256(data : Seq[Byte]): Array[Byte] = {
    MessageDigest.getInstance("SHA-256").digest(data.toArray)
  }

  class PrivateKey(D: BigInteger) {
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
    def sign(data: Seq[Byte], includeRecoveryByte: Boolean): String = {
      signHash(sha256(data), includeRecoveryByte)
    }

    /**
      * Convert this private key to an array of bytes
      * @return An array of bytes, with the same number of bytes as the curve modulus
      */
    def toByteArray: Array[Byte] = {
      val bytes: Array[Byte] = D.toByteArray.dropWhile(_ == 0)
      assert(bytes.length * 8 <= curve.getN.bitLength,
             "Private key cannot have more than " + curve.getN.bitLength +
             " bits (had " + bytes.length * 8 + ")")
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
        messageHash: Seq[Byte]): Iterator[BigInteger] = {
      assert(
          curveBytes == messageHash.length,
          "Hashed input is not the same length as the number of bytes in the curve")
      val kCalculator = new HMacDSAKCalculator(new SHA256Digest)
      kCalculator.init(curve.getN, key.getD, messageHash.toArray)
      new Iterator[BigInteger] {
        val hasNext: Boolean = true
        def next(): BigInteger = kCalculator.nextK()
      }
    }

    private def ecdsaDERBytes(r: BigInteger, s: BigInteger): Array[Byte] = {
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
    def signHash(messageHash: Seq[Byte], includeRecoveryByte: Boolean = true): String = {
      // Generate an RFC 6979 compliant signature
      // See: https://tools.ietf.org/html/rfc6979
      assert(
          curveBytes == messageHash.length,
          "Hashed input is not the same length as the number of bytes in the curve")
      val z = new BigInteger(1, messageHash.toArray)
      val n = curve.getN
      val bigZero = BigInteger.ZERO
      case class Parameters(recoveryByte: Byte, r: BigInteger, s: BigInteger)
      getDeterministicKGenerator(messageHash).map { k =>
        val kp = curve.getG.multiply(k).normalize
        val r = kp.getXCoord.toBigInteger.mod(n)
        val _s = k.modInverse(n).multiply(r.multiply(D).add(z)).mod(n)
        val s = if (_s.add(_s).compareTo(n) == -1) _s else n.subtract(_s)
        val recoveryByte =
          (0x1B + (if (kp.getYCoord.toBigInteger.testBit(0) ^ _s != s) 1
                   else 0) + (if (r.compareTo(n) == -1) 0 else 2)).toByte
        Parameters(recoveryByte, r, s)
      }.filterNot { p =>
        (p.r equals bigZero) || (p.s equals bigZero)
      }.map { p =>
        (if (includeRecoveryByte) Array(p.recoveryByte) else Array.empty) ++
        ecdsaDERBytes(p.r, p.s)
      }.map(BaseConvert.encode(_, defaultBase)).map(_.toLowerCase).next()
    }

    /**
      * Get the public key that corresponds to this private key
      * @return This private key's corresponding public key
      */
    def getPublicKey: PublicKey = {
      new PublicKey(curve.getG.multiply(D).normalize)
    }

    /**
      * Output a string representing this private key
      * @return A hexadecimal string
      */
    override def toString = D.toString(defaultBase)

    //noinspection ComparingUnrelatedTypes
    def canEqual(other: Any): Boolean = other.isInstanceOf[PrivateKey]

    override def equals(other: Any): Boolean = other match {
      case that: PrivateKey =>
        (that canEqual this) && D == that.key.getD
      case _ => false
    }

    override def hashCode(): Int = {
      val state = Seq(curve, key)
      state.map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
    }
  }

  object PrivateKey {

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
      apply(input, defaultBase)
    }

    /**
      * Construct a private key from a byte array
      * @param input A byte array
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: Seq[Byte]): PrivateKey = {
      new PrivateKey(new BigInteger(1, input.toArray))
    }

    /**
      * Construct a private key from a string with specified base
      * @param input A string with the specified base
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: String, base: Int): PrivateKey = {
      new PrivateKey(new BigInteger(1, BaseConvert.decode(input, base)))
    }

    /**
      * Construct a private key from a BigInteger
      * @param input A hexadecimal string
      * @return A private key with exponent D corresponding to the input
      */
    def apply(input: BigInteger): PrivateKey = {
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
    private val point = _point.normalize
    private val key = new ECPublicKeyParameters(point, curve)
    private val verifier = new ECDSASigner()
    verifier.init(false, key)

    /**
      * Convert to a compressed X.509 encoded hexadecimal string
      * @return A compressed X.509 encoded hexadecimal string
      */
    override def toString: String = {
      PublicKey.encodeECPoint(key.getQ, defaultBase, compressed = true)
    }

    /**
      * Convert to a X.509 encoded hexadecimal string
      * @param compressed Boolean whether to output a compressed key or not
      * @return A X.509 encoded hexadecimal string
      */
    def toString(compressed: Boolean): String = {
      PublicKey.encodeECPoint(key.getQ, defaultBase, compressed)
    }

    /**
      * Convert to a compressed X.509 encoded string
      * @param base The base to encode the string to
      * @return A compressed X.509 encoded string
      */
    def toString(base: Int): String = {
      PublicKey.encodeECPoint(key.getQ, base, compressed = true)
    }

    /**
      * Convert to a X.509 encoded string
      * @param base The base to encode the string to
      * @param compressed Boolean whether to output a compressed key or not
      * @return A X.509 encoded string
      */
    def toString(base: Int, compressed: Boolean): String = {
      PublicKey.encodeECPoint(key.getQ, base, compressed)
    }

    private def verifyECDSA(hash: Seq[Byte], signature: Seq[Byte]): Boolean = {
      val decoder = new ASN1InputStream(signature.toArray)
      try {
        val sequence = decoder.readObject().asInstanceOf[DLSequence]
        val r = sequence.getObjectAt(0).asInstanceOf[ASN1Integer].getValue
        val s = sequence.getObjectAt(1).asInstanceOf[ASN1Integer].getValue
        verifier.verifySignature(hash.toArray, r, s)
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
    def verifyHash(hash: Seq[Byte], signature: Seq[Byte]): Boolean = {
      assert(hash.length * 8 == curve.getN.bitLength,
             "Hash must have " + curve.getN.bitLength + "bits (had " +
             hash.length * 8 + " bits)")
      signature.head match {
        case 0x1B | 0x1C | 0x1D | 0x1E =>
          this == PublicKey.recoverPublicKeyFromHash(
              hash.toArray, signature.toArray)
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
    def verify(input: Seq[Byte], signature: Seq[Byte]): Boolean = {
      verifyHash(sha256(input), signature)
    }

    /**
      * Verify a signature against this public key
      * @param input Bytes to be hashed and then verified
      * @param signature The ECDSA signature bytes as a hex string
      * @return Boolean whether the signature is valid
      */
    def verify(input: Seq[Byte], signature: String): Boolean = {
      verify(input, BaseConvert.decode(signature, defaultBase))
    }

    /**
      * Verify a signature against this public key
      * @param input UTF-8 encoded string to be hashed and then verified
      * @param signature The ECDSA signature bytes
      * @return Boolean whether the signature is valid
      */
    def verify(input: String, signature: Seq[Byte]): Boolean = {
      verify(input.getBytes("UTF-8"), signature)
    }

    /**
      * Verify a signature against this public key
      * @param input UTF-8 encoded string to be hashed and then verified
      * @param signature The ECDSA signature bytes as a hex string
      * @return Boolean whether the signature is valid
      */
    def verify(input: String, signature: String): Boolean = {
      verify(input, BaseConvert.decode(signature, defaultBase))
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
        }
      case _ => false
    }

    override def hashCode(): Int = {
      val state = Seq(curve, key)
      state.map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
    }
  }

  object PublicKey {
    private def encodeXCoordinate(
        yEven: Boolean, xCoordinate: BigInteger): Array[Byte] = {
      val xCoordinateBytes = xCoordinate.toByteArray.dropWhile(_ == 0)
      assert(
        xCoordinateBytes.length <= curveBytes,
          "Input:\n\n" + xCoordinate + "\n\ncannot have more than " +
            curveBytes + " bytes, the number of bytes in the curve modulus (had " +
            xCoordinateBytes.length + " bytes)")
      Array[Byte](if (yEven) 0x02 else 0x03) ++ xCoordinateBytes
    }

    private def encodeECPoint(
        point: ECPoint, base: Int, compressed: Boolean = true): String = {
      BaseConvert.encode(point.getEncoded(compressed), base)
    }

    private def decodeECPoint(input: String, base: Int): ECPoint = {
      decodeECPoint(BaseConvert.decode(input, base))
    }

    private def decodeECPoint(input: Seq[Byte]): ECPoint = {
      curve.getCurve.decodePoint(input.toArray).normalize
    }

    /**
      * Construct a PublicKey from an X.509 encoded hexadecimal string
      * @param input An X.509 encoded hexadecimal string
      * @return The corresponding public key
      */
    def apply(input: String): PublicKey = {
      new PublicKey(decodeECPoint(input, defaultBase))
    }

    /**
      * Construct a PublicKey from an X.509 encoded string
      * @param input An X.509 encoded hexadecimal string
      * @param base The base of the encoded string
      * @return The corresponding public key
      */
    def apply(input: String, base: Int): PublicKey = {
      new PublicKey(decodeECPoint(input, base))
    }

    /**
      * Construct a PublicKey from an X.509 encoded byte sequence
      * @param input An X.509 encoded byte sequence
      * @return The corresponding public key
      */
    def apply(input: Seq[Byte]): PublicKey = {
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
    def ecrecover(hash: Seq[Byte],
                  recoveryByte: Byte,
                  r: BigInteger,
                  s: BigInteger): PublicKey = {
      assert(hash.length * 8 == curve.getN.bitLength,
             "Hash must have " + curve.getN.bitLength + "bits (had " +
             hash.length * 8 + " bits)")
      assert(0x1B <= recoveryByte && recoveryByte <= 0x1E,
             "Recovery byte must be 0x1B, 0x1C, 0x1D, or 0x1E")
      assert(
          r.toByteArray.dropWhile(_ == 0).length * 4 <= curve.getN.bitLength,
          "R component out of range")
      assert(
          s.toByteArray.dropWhile(_ == 0).length * 4 <= curve.getN.bitLength,
          "S component out of range")
      val yEven = ((recoveryByte - 0x1B) & 1) == 0
      val isSecondKey = ((recoveryByte - 0x1B) >> 1) == 1
      val n = curve.getN
      val p = curve.getCurve.getField.getCharacteristic
      if (isSecondKey)
        assert(
            r.compareTo(p.mod(n)) >= 0, "Unable to find second key candidate")
      // 1.1. Let x = r + jn.
      val R = decodeECPoint(
          encodeXCoordinate(yEven, if (isSecondKey) r.add(n) else r))
      val eInv = n.subtract(new BigInteger(1, hash.toArray))
      val rInv = r.modInverse(n)
      // 1.6.1 Compute Q = r^-1 (sR + -eG)
      new PublicKey(
          ECAlgorithms
            .sumOfTwoMultiplies(curve.getG, eInv, R, s)
            .multiply(rInv)
            .normalize)
    }

    /**
      * Recover a public key from signed data and an extended signature
      * @param input The data as a hexadecimal string (to be hashed)
      * @param signature A hexadecimal signature
      * @return The public key recovered
      */
    def recoverPublicKey(input: String, signature: String): PublicKey = {
      recoverPublicKey(input, BaseConvert.decode(signature, defaultBase))
    }

    /**
      * Recover a public key from signed data and an extended signature
      * @param input The data as a hexadecimal string (to be hashed)
      * @param signature A signature as a byte sequence
      * @return The public key recovered
      */
    def recoverPublicKey(input: String, signature: Seq[Byte]): PublicKey = {
      recoverPublicKey(input.getBytes("UTF-8"), signature)
    }

    /**
      * Recover a public key from signed data and an extended signature
      * @param input The data as a byte sequence (to be hashed)
      * @param signature A hexadecimal signature
      * @return The public key recovered
      */
    def recoverPublicKey(input: Seq[Byte], signature: String): PublicKey = {
      recoverPublicKey(input, BaseConvert.decode(signature, defaultBase))
    }

    /**
      * Recover a public key from signed data and an extended signature
      * @param input The data as a byte sequence (to be hashed)
      * @param signature A hexadecimal signature
      * @return The public key recovered
      */
    def recoverPublicKey(input: Seq[Byte], signature: Seq[Byte]): PublicKey = {
      recoverPublicKeyFromHash(sha256(input), signature)
    }

    /**
      * Recover a public key from a hash and an extended signature
      * @param hash The hash of the signed data as a byte sequence
      * @param signature The signature as a byte sequence
      * @return The public key recovered
      */
    def recoverPublicKeyFromHash(
        hash: Seq[Byte], signature: Seq[Byte]): PublicKey = {
      assert(hash.length * 8 == curve.getN.bitLength,
             "Hash must have " + curve.getN.bitLength + "bits (had " +
             hash.length * 8 + " bits)")
      val decoder = new ASN1InputStream(
          signature.toArray.slice(1, signature.length))
      try {
        val recoveryByte = signature.head
        val sequence = decoder.readObject().asInstanceOf[DLSequence]
        val r: BigInteger =
          sequence.getObjectAt(0).asInstanceOf[ASN1Integer].getValue
        val s: BigInteger =
          sequence.getObjectAt(1).asInstanceOf[ASN1Integer].getValue
        ecrecover(hash, recoveryByte, r, s)
      } finally {
        decoder.close()
      }
    }
  }
}
