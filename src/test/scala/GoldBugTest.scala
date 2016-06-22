import java.math.BigInteger
import java.security.MessageDigest

import gold.bug.HashUtil
import gold.bug.addresses.{BitCoinAddress, EthereumAddress}
import gold.bug.formatting.BaseConvert
import gold.bug.secp256k1.Curve._
import org.scalatest.FunSpec

class GoldBugTest extends FunSpec {
  def toHex(buf: Array[Byte]): String =
    buf.map("%02x" format _).mkString
  def sha256(s: String): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8"))

  describe("PublicKey From Known PrivateKey") {
    it("Should default to outputting compressed keys") {
      assert(
          "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1" == PrivateKey(
              "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c").publicKey.toString)
    }
    it("Should handle optionally outputting an uncompressed key") {
      assert(
          "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c" == PrivateKey(
              "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c").publicKey
            .toString(compressed = false))
    }
  }

  describe("Testing a number of known private key and public key pairs") {
    val priv1 =
      "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c"
    val pub1 =
      "02326209e52f6f17e987ec27c56a1321acf3d68088b8fb634f232f12ccbc9a4575"
    describe("Pair 1") {
      it("Can convert to a string and back") {
        assert(PrivateKey(PrivateKey(priv1).toString) == PrivateKey(priv1))
        assert(PrivateKey(PrivateKey(priv1).toByteArray) == PrivateKey(priv1))
        assert(PrivateKey(PrivateKey(priv1).toString(58), 58) == PrivateKey(
                priv1))
        assert(PrivateKey(PrivateKey(priv1).toString(64), 64) == PrivateKey(
                priv1))
        assert(PrivateKey(PrivateKey(priv1).toString(10), 10) == PrivateKey(
                priv1))
      }
      it("Can properly derive a public key") {
        assert(PublicKey(PrivateKey(priv1)) == PublicKey(pub1))
      }
      it("Can encoded and decode a public key") {
        assert(PublicKey(PublicKey(pub1).toString) == PublicKey(pub1))
        assert(
            PublicKey(PublicKey(pub1).toString(compressed = false)) == PublicKey(
                pub1))
      }
    }

    val priv2 =
      "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
    val pub2 =
      "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
    describe("Pair 2") {
      it("Can convert to a string and back") {
        assert(PrivateKey(PrivateKey(priv2, 16).toString) == PrivateKey(priv2))
      }
      it("Can properly derive a public key") {
        assert(PrivateKey(priv2).publicKey == PublicKey(pub2))
      }
      it("Can encoded and decode a public key") {
        assert(PublicKey(PublicKey(pub2).toString) == PublicKey(pub2))
        assert(
            PublicKey(PublicKey(pub2).toString(compressed = false)) == PublicKey(
                pub2))
      }
      it("Private key is different than the one in Pair 1") {
        assert(PrivateKey(PrivateKey(priv2).toString) != PrivateKey(priv1))
      }
      it("Public key is different than the one in Pair 1") {
        assert(
            PublicKey(PublicKey(pub2).toString) != PublicKey(PublicKey(pub1)))
      }
    }
  }

  describe("Pair 3") {
    val priv =
      "e9d5516cb0ae45952fa11473a469587d6c0e8aeef3d6b0cca6f4497c725f314c"
    val pub =
      "033142109aba8e415c73defc83339dcec52f40ce762421c622347a7840294b3423"
    it("Can convert to a string and back") {
      assert(PrivateKey(PrivateKey(priv).toString) == PrivateKey(priv))
    }
    it("Can properly derive a public key") {
      assert(PrivateKey(priv).publicKey == PublicKey(pub))
    }
    it("Can encoded and decode a public key") {
      assert(PublicKey(PublicKey(pub).toString) == PublicKey(pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(compressed = false)) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(58, compressed = false), 58) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(64, compressed = false), 64) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(10, compressed = false), 10) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(compressed = true)) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(58, compressed = true), 58) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(64, compressed = true), 64) == PublicKey(
              pub, 16))
      assert(
          PublicKey(PublicKey(pub).toString(10, compressed = true), 10) == PublicKey(
              pub, 16))
    }
  }

  describe("Pair 4") {
    val priv =
      "9e15c053f17c0991163073a73bc7e4b234c6c55c5f85bb397ed39f14c46a64bd"
    val pub =
      "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"
    it("Can convert to a string and back") {
      assert(PrivateKey(PrivateKey(priv).toString) == PrivateKey(priv))
    }
    it("Can properly derive a public key") {
      assert(PrivateKey(priv).publicKey == PublicKey(pub))
    }
    it("Can encoded and decode a public key") {
      assert(PublicKey(PublicKey(pub).toString) == PublicKey(pub))
      assert(
          PublicKey(PublicKey(pub).toString(compressed = false)) == PublicKey(
              pub))
    }
  }

  describe("Signature Tests") {
    val privKey = PrivateKey(
        "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0", 16)
    val pubKey = privKey.publicKey

    it("Should compute the public key properly") {
      assert(
          pubKey.toString == "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58")
    }

    it("Should be able to verify reference signatures") {
      assert(pubKey.verify(
              "foo",
              "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"))

      assert(pubKey.verify(
              "baz",
              "304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae"))

      assert(pubKey.verify(
              "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!",
              "304402204c818a10380ba42b3be0a293d47922469c4ae7ad6277e0e62bf32700c79c32210220102b673477ee13877b4b7f8f9a2e4c2004553948fbe5e7fd95d7e23b4cd9f8e3"))

      assert(pubKey.verify(
              "☕️   ⓝ  🀤  ⎈  ∲",
              "304502204d78e57e9bce7fc6d3dd61bcd1baaceff2689f9a8efac5bbb8ce59a47f6652120221008bdce60d43916e35db9c8ee889ba2f85acd2a98fa0193cce0a7f9f9d9867aac1"))

      assert(pubKey.verify(
              "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड",
              "304602210087d7aad4dc2789b8f58f97f541f95fc150ffc7fad8e09093932c023b13330e1a022100b434f9403048a983f8dfbd9b92ad8e2dac1ec4b1934dec8c94f4165bf981e01c"))

      assert(pubKey.verify(
              "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다.",
              "3044022030e9acbd8f0f3328bd059296092824a38216a222d04ac7e1f3de89d4270f3e18022014386f61154177111fe1da0eee9874e612990d3ce663e6f2b4c44828b4c7072f"))

      assert(pubKey.verify(
              "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。",
              "3046022100b286833ddce1537e12f56ae63fbbd6db25ac0dfab659d342a323b764765b60c0022100d83878b0529bf2cab70e98929faf11d1836d8452ef978aad558e35cce4fb14c4"))

      assert(pubKey.verify(
              "ဂျူးလိယက်ဆီဇာ(ဘီစီ၁၀၀-၄၄)",
              "304402206ba84011c961db733e28f40f2496e8ff1ba60fcbf942b609fd1a9a6971f22e5b02202987d7d6ad5c330c7fdacefe3351554c00f42b82b7ad513104de8caebae40fc8"))

      assert(pubKey.verify(
              "རོ་མའི་རང་དབང་འབངས་མི་ཞིག་ལ་མིང་གསུམ་ཡོད་དེ།",
              "304402200e4b0560c42e4de19ddc2541f5531f7614628e9d01503d730ebe38c182baee8702206b80868e3d67fec2a9d5a594edd6b4f0266044965fe41e7cc3bff65feb922b7c"))
    }

    it("Should not verify bad signatures") {
      assert(!pubKey.verify(
              "fooo",
              "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"))
      assert(!pubKey.verify(
              "baz1",
              "304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae"))

      assert(!pubKey.verify(
              "What a piece of work is a man!",
              "304402204c818a10380ba42b3be0a293d47922469c4ae7ad6277e0e62bf32700c79c32210220102b673477ee13877b4b7f8f9a2e4c2004553948fbe5e7fd95d7e23b4cd9f8e3"))

      assert(!pubKey.verify(
              "☕️   ⓝ  🀤  ⎈  ∲ 999",
              "304502204d78e57e9bce7fc6d3dd61bcd1baaceff2689f9a8efac5bbb8ce59a47f6652120221008bdce60d43916e35db9c8ee889ba2f85acd2a98fa0193cce0a7f9f9d9867aac1"))

      assert(!pubKey.verify(
              "इइसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड",
              "304602210087d7aad4dc2789b8f58f97f541f95fc150ffc7fad8e09093932c023b13330e1a022100b434f9403048a983f8dfbd9b92ad8e2dac1ec4b1934dec8c94f4165bf981e01c"))

      assert(!pubKey.verify(
              "도금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다.",
              "3044022030e9acbd8f0f3328bd059296092824a38216a222d04ac7e1f3de89d4270f3e18022014386f61154177111fe1da0eee9874e612990d3ce663e6f2b4c44828b4c7072f"))

      assert(!pubKey.verify(
              "ドリ上科コトドリ科コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。",
              "3046022100b286833ddce1537e12f56ae63fbbd6db25ac0dfab659d342a323b764765b60c0022100d83878b0529bf2cab70e98929faf11d1836d8452ef978aad558e35cce4fb14c4"))

      assert(!pubKey.verify(
              "ဂျူးလက်ဆီဇိယက်ဆီဇာ(ဘီစီ၁၀၀-၄၄)",
              "304402206ba84011c961db733e28f40f2496e8ff1ba60fcbf942b609fd1a9a6971f22e5b02202987d7d6ad5c330c7fdacefe3351554c00f42b82b7ad513104de8caebae40fc8"))

      assert(!pubKey.verify(
              "རོ་མའི་རང་དབང་འབངས་མམ་ཡོད་དེ།",
              "304402200e4b0560c42e4de19ddc2541f5531f7614628e9d01503d730ebe38c182baee8702206b80868e3d67fec2a9d5a594edd6b4f0266044965fe41e7cc3bff65feb922b7c"))
    }

    it("Should verify ECDSA signatures signed by the public key's private key") {
      def check(data: String): Boolean = {
        pubKey.verify(data, privKey.sign(data, includeRecoveryByte = false))
      }
      assert(check("foo"))
      assert(check("bar"))
      assert(check("barr"))
      assert(check("barrr"))
      assert(check("yabba dabba dooo"))
      assert(
          check("I wanna hold 'em like they do in Texas, please\n" +
              "Fold 'em, let 'em, hit me, raise it, baby, stay with me (I love it)\n" +
              "Love game intuition play the cards with Spades to start\n" +
              "And after he's been hooked I'll play the one that's on his heart"))
      assert(check("☕️   ⓝ  🀤  ⎈  ∲"))
      assert(check(
              "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"))
      assert(
          check("금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."))
      assert(
          check("コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"))
    }

    it("Should verify signatures extended with a recovery byte signed by the public key's private key") {
      def check(data: String): Boolean = {
        pubKey.verify(data, privKey.sign(data, includeRecoveryByte = true))
      }
      assert(check("foo"))
      assert(check("bar"))
      assert(check("barr"))
      assert(check("barrr"))
      assert(check("yabba dabba dooo"))
      assert(
          check("I wanna hold 'em like they do in Texas, please\n" +
              "Fold 'em, let 'em, hit me, raise it, baby, stay with me (I love it)\n" +
              "Love game intuition play the cards with Spades to start\n" +
              "And after he's been hooked I'll play the one that's on his heart"))
      assert(check("☕️   ⓝ  🀤  ⎈  ∲"))
      assert(check(
              "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"))
      assert(
          check("금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."))
      assert(
          check("コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"))
    }

    it("Should not verify signatures signed by some random private key") {
      def check(data: String): Boolean = {
        val randomPrivKey = PrivateKey.generateRandom
        !pubKey.verify(data, randomPrivKey.sign(data))
      }
      assert(check("foo"))
      assert(check("bar"))
      assert(check("yabba dabba dooo"))
      assert(
          check("I wanna hold 'em like they do in Texas, please\n" +
              "Fold 'em, let 'em, hit me, raise it, baby, stay with me (I love it)\n" +
              "Love game intuition play the cards with Spades to start\n" +
              "And after he's been hooked I'll play the one that's on his heart"))
      assert(check("☕️   ⓝ  🀤  ⎈  ∲"))
      assert(check(
              "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"))
      assert(
          check("금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."))
      assert(
          check("コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"))
    }
  }

  describe("Deterministic random number generation") {
    it("Should handle test values generated by python-ecdsa 0.9") {
      /* Code to make your own vectors:

         ```
         class gen:
             def order(self): return 115792089237316195423570985008687907852837564279074904382605163141518161494337
         dummy = gen()
         for i in range(10): ecdsa.rfc6979.generate_k(dummy, i, hashlib.sha256, hashlib.sha256(str(i)).digest())
         ```
       */
      def encode(i: Int, length: Int): Array[Byte] =
        Array.fill[Byte](length - 1)(0x00) ++ Array(i.toByte)
      def check(i: Int): BigInteger =
        PrivateKey(encode(i, 32))
          .getDeterministicKGenerator(sha256(i.toString))
          .next
      assert(
          toHex(sha256(0.toString)) == "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9")
      assert(
          toHex(encode(0, 32)) == "0000000000000000000000000000000000000000000000000000000000000000")
      assert(
          toHex(check(0).toByteArray) == "487ab3b9b831a0a439036815b299567ca10f97b1ffd6d8fdf01f1554dcd8885d")
      assert(
          toHex(check(1).toByteArray) == "00f24af0377e1b27fbebae63b3bec9b249b5bb0b0ba975896dbf35d79b189d19d3")
      assert(
          toHex(check(2).toByteArray) == "009165e4c79e832d82445a50a4a4ec563001e682d6142a5bd6664a0ac25d8759b0")
    }
  }

  describe("Deterministic Signature Tests") {
    val privKey = PrivateKey(
        "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0", 16)
    it("Should deterministically produce signatures according to RFC 6979") {
      assert(
          privKey.sign("foo") == "1c3045022100927247ae8b1d692d99096ea0a352ca99a4af84377af8152ccca671f24bc6169702206c3d28b9025d618c20612c4fdde67f052abf0e5e08c471c5c88baa96ce9538e1")
      assert(
          privKey.sign("barr") == "1b3045022100c738f07424690873da0afadd04a9afd4aedb3abe6db7cea6daed06a211c6dd6f02201c386378ab4e9438af27601a9887c361dd3c9661d04322c94393edb7cd8cd512")
    }
  }

  describe("Can decode and encode a version 1 BitCoin address") {
    val privKey =
      "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
    val address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    it("Should decode and then encode") {
      assert(BitCoinAddress(address).toString == address)
    }
    it("Should decode and then encode using base 10") {
      assert(
          BitCoinAddress(BitCoinAddress(address).toString(10), 10) == BitCoinAddress(
              address))
    }
    it("Should decode and then encode using base 16") {
      assert(
          BitCoinAddress(BitCoinAddress(address).toString(16), 16) == BitCoinAddress(
              address))
    }
    it("Should decode and then encode using base 64") {
      assert(
          BitCoinAddress(BitCoinAddress(address).toString(64), 64) == BitCoinAddress(
              address))
    }
    it("Should decode and then encode using a byte array") {
      assert(
          BitCoinAddress(BitCoinAddress(address).toByteArray) == BitCoinAddress(
              address))
    }
    it("Should compute a BitCoin address from a known private key") {
      assert(BitCoinAddress(PrivateKey(privKey)) == BitCoinAddress(address))
    }
  }

  describe("Sad Path: throws security errors on invalid BitCoin addresses") {
    val address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    it("Should throw a SecurityException when the BitCoin address has a transcription error") {
      intercept[SecurityException] {
        BitCoinAddress("foo")
      }
      intercept[SecurityException] {
        BitCoinAddress("bar")
      }
      intercept[SecurityException] {
        BitCoinAddress("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvm")
      }
      intercept[SecurityException] {
        BitCoinAddress(address.toLowerCase)
      }
      intercept[SecurityException] {
        BitCoinAddress(address.toUpperCase)
      }
      intercept[SecurityException] {
        BitCoinAddress(address + "M")
      }
      intercept[SecurityException] {
        BitCoinAddress("0x52908400098527886E0F7030069857D2E4169Ee7")
      }
      intercept[SecurityException] {
        BitCoinAddress(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
      }
    }
  }

  describe("Obviated SHA3 Ethereum uses everywhere tests") {
    it("Should have keccak256 properly implemented, not the modern NIST SHA3 hash") {
      // http://ethereum.stackexchange.com/a/560
      assert(BaseConvert.encode(
              HashUtil.keccak256(BaseConvert.decode("", 16)),
              16) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
      assert(
          BaseConvert.encode(
              HashUtil.keccak256(
                  "The quick brown fox jumps over the lazy dog"),
              16) == "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15")
      assert(
          BaseConvert.encode(
              HashUtil.keccak256(
                  "The quick brown fox jumps over the lazy dog."),
              16) == "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d")
    }
  }

  describe("Can decode and encode an Ethereum address") {
    it("Should properly parse and reprint valid Ethereum addresses" +
        " taken from https://github.com/8go/go-ethereum/blob/master/crypto/crypto_test.go#L251") {
      def check(address: String) =
        assert(EthereumAddress(address).toString == address)
      Seq("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
          "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
          "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
          "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
          "0x5A4EAB120fB44eb6684E5e32785702FF45ea344D",
          "0x5be4BDC48CeF65dbCbCaD5218B1A7D37F58A0741",
          "0xa7dD84573f5ffF821baf2205745f768F8edCDD58",
          "0x027a49d11d118c0060746F1990273FcB8c2fC196",
          "0x689E3fE51F45760Ab73D237d28fc1d2C8EaC6D71",
          "0x97D509F0b388daE6D000C33193F4645D1e71Dc54",
          "0xa4Fd5bD20Cf5A7CF1c5A6015D2b3e08A3eC1b1a7",
          "0x230AE42Daf56B494E4b9E6D8Cce99F5E14FE29c1",
          "0xC19D1EDB7FC943f2abbF576f6058c2425B347AB9",
          "0x4f936Bb00CaaD116adc3861146dd8f68BF66F4E6",
          "0xE74287ECA7B7151Fd194cdf7680EB50752671c47",
          "0x5d32a30FBc5bddF39293CE3a9D74E4505dEb621D",
          "0x27cBC66cbE3625c2857ce3CF77A9933e589545DF",
          "0xE2A5f301EA7e461880Fe9A6B4b7EC1aBD023129A",
          "0xe0DFdDA1D174aB7315C753EA198885ee88B52763",
          "0x843655C78939365298FD9515b489939bADca64Ec",
          "0x6bB7a54E4ef381e4C64009DDa0A9ED127aab852C").foreach(check)
    }

    it("Should properly parse and reprint valid Ethereum addresses that have been converted into byte arrays") {
      def check(address: String) =
        assert(EthereumAddress(BaseConvert.decode(address, 16)) ==
            EthereumAddress(address))
      Seq("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
          "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
          "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
          "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
          "0x5A4EAB120fB44eb6684E5e32785702FF45ea344D",
          "0x5be4BDC48CeF65dbCbCaD5218B1A7D37F58A0741",
          "0xa7dD84573f5ffF821baf2205745f768F8edCDD58",
          "0x027a49d11d118c0060746F1990273FcB8c2fC196",
          "0x689E3fE51F45760Ab73D237d28fc1d2C8EaC6D71",
          "0x97D509F0b388daE6D000C33193F4645D1e71Dc54",
          "0xa4Fd5bD20Cf5A7CF1c5A6015D2b3e08A3eC1b1a7",
          "0x230AE42Daf56B494E4b9E6D8Cce99F5E14FE29c1",
          "0xC19D1EDB7FC943f2abbF576f6058c2425B347AB9",
          "0x4f936Bb00CaaD116adc3861146dd8f68BF66F4E6",
          "0xE74287ECA7B7151Fd194cdf7680EB50752671c47",
          "0x5d32a30FBc5bddF39293CE3a9D74E4505dEb621D",
          "0x27cBC66cbE3625c2857ce3CF77A9933e589545DF",
          "0xE2A5f301EA7e461880Fe9A6B4b7EC1aBD023129A",
          "0xe0DFdDA1D174aB7315C753EA198885ee88B52763",
          "0x843655C78939365298FD9515b489939bADca64Ec",
          "0x6bB7a54E4ef381e4C64009DDa0A9ED127aab852C").foreach(check)
    }

    it("Should properly parse valid Ethereum addresses," +
        " convert them to byte arrays," +
        " and convert them back into Ethereum addresses") {
      def check(address: String) =
        assert(EthereumAddress(EthereumAddress(address).toByteArray) ==
            EthereumAddress(address))
      Seq("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
          "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
          "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
          "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
          "0x5A4EAB120fB44eb6684E5e32785702FF45ea344D",
          "0x5be4BDC48CeF65dbCbCaD5218B1A7D37F58A0741",
          "0xa7dD84573f5ffF821baf2205745f768F8edCDD58",
          "0x027a49d11d118c0060746F1990273FcB8c2fC196",
          "0x689E3fE51F45760Ab73D237d28fc1d2C8EaC6D71",
          "0x97D509F0b388daE6D000C33193F4645D1e71Dc54",
          "0xa4Fd5bD20Cf5A7CF1c5A6015D2b3e08A3eC1b1a7",
          "0x230AE42Daf56B494E4b9E6D8Cce99F5E14FE29c1",
          "0xC19D1EDB7FC943f2abbF576f6058c2425B347AB9",
          "0x4f936Bb00CaaD116adc3861146dd8f68BF66F4E6",
          "0xE74287ECA7B7151Fd194cdf7680EB50752671c47",
          "0x5d32a30FBc5bddF39293CE3a9D74E4505dEb621D",
          "0x27cBC66cbE3625c2857ce3CF77A9933e589545DF",
          "0xE2A5f301EA7e461880Fe9A6B4b7EC1aBD023129A",
          "0xe0DFdDA1D174aB7315C753EA198885ee88B52763",
          "0x843655C78939365298FD9515b489939bADca64Ec",
          "0x6bB7a54E4ef381e4C64009DDa0A9ED127aab852C").foreach(check)
    }

    it("Should properly parse valid Ethereum addresses," +
      " convert them to base 58," +
      " and convert them back into Ethereum addresses") {
      def check(address: String) =
        assert(EthereumAddress(EthereumAddress(address).toByteArray) ==
          EthereumAddress(address))
      Seq("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0x5A4EAB120fB44eb6684E5e32785702FF45ea344D",
        "0x5be4BDC48CeF65dbCbCaD5218B1A7D37F58A0741",
        "0xa7dD84573f5ffF821baf2205745f768F8edCDD58",
        "0x027a49d11d118c0060746F1990273FcB8c2fC196",
        "0x689E3fE51F45760Ab73D237d28fc1d2C8EaC6D71",
        "0x97D509F0b388daE6D000C33193F4645D1e71Dc54",
        "0xa4Fd5bD20Cf5A7CF1c5A6015D2b3e08A3eC1b1a7",
        "0x230AE42Daf56B494E4b9E6D8Cce99F5E14FE29c1",
        "0xC19D1EDB7FC943f2abbF576f6058c2425B347AB9",
        "0x4f936Bb00CaaD116adc3861146dd8f68BF66F4E6",
        "0xE74287ECA7B7151Fd194cdf7680EB50752671c47",
        "0x5d32a30FBc5bddF39293CE3a9D74E4505dEb621D",
        "0x27cBC66cbE3625c2857ce3CF77A9933e589545DF",
        "0xE2A5f301EA7e461880Fe9A6B4b7EC1aBD023129A",
        "0xe0DFdDA1D174aB7315C753EA198885ee88B52763",
        "0x843655C78939365298FD9515b489939bADca64Ec",
        "0x6bB7a54E4ef381e4C64009DDa0A9ED127aab852C").foreach(check)
    }

    it("Should parse properly even if the leading 0x is omitted from valid Ethereum addresses" +
        " taken from https://github.com/8go/go-ethereum/blob/master/crypto/crypto_test.go#L251") {
      def check(address: String) =
        assert(
            EthereumAddress(address).toString.replaceFirst("^0x", "") == address)
      Seq("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
          "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
          "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
          "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
          "5A4EAB120fB44eb6684E5e32785702FF45ea344D",
          "5be4BDC48CeF65dbCbCaD5218B1A7D37F58A0741",
          "a7dD84573f5ffF821baf2205745f768F8edCDD58",
          "027a49d11d118c0060746F1990273FcB8c2fC196",
          "689E3fE51F45760Ab73D237d28fc1d2C8EaC6D71",
          "97D509F0b388daE6D000C33193F4645D1e71Dc54",
          "a4Fd5bD20Cf5A7CF1c5A6015D2b3e08A3eC1b1a7",
          "230AE42Daf56B494E4b9E6D8Cce99F5E14FE29c1",
          "C19D1EDB7FC943f2abbF576f6058c2425B347AB9",
          "4f936Bb00CaaD116adc3861146dd8f68BF66F4E6",
          "E74287ECA7B7151Fd194cdf7680EB50752671c47",
          "5d32a30FBc5bddF39293CE3a9D74E4505dEb621D",
          "27cBC66cbE3625c2857ce3CF77A9933e589545DF",
          "E2A5f301EA7e461880Fe9A6B4b7EC1aBD023129A",
          "e0DFdDA1D174aB7315C753EA198885ee88B52763",
          "843655C78939365298FD9515b489939bADca64Ec",
          "6bB7a54E4ef381e4C64009DDa0A9ED127aab852C").foreach(check)
    }

    it("Should properly parse valid lower case legacy Ethereum addresses" +
        " taken from https://github.com/8go/go-ethereum/blob/master/crypto/crypto_test.go#L251") {
      def check(address: String) =
        assert(EthereumAddress(address).toString.toLowerCase == address)
      Seq("0xde709f2102306220921060314715629080e2fb77",
          "0x27b1fdb04752bbc536007a920d24acb045561c26").foreach(check)
    }

    it("Should properly parse valid upper case legacy Ethereum addresses" +
        " taken from https://github.com/8go/go-ethereum/blob/master/crypto/crypto_test.go#L251") {
      def check(address: String) =
        assert(EthereumAddress(address).toString.toUpperCase
              .replaceFirst("^0X", "0x") == address)
      Seq("0x52908400098527886E0F7030069857D2E4169EE7",
          "0x8617E340B3D01FA5F11F306F4090FD50E238070D").foreach(check)
    }

    it("Sad Paths: SecurityExceptions should be thrown for bad addresses") {
      def check(address: String) =
        intercept[SecurityException] {
          EthereumAddress(address)
        }
      Seq("0x52908400098527886E0F7030069857D2E4169Ee7",
          "0x8617E340B3D01FA5F11F306F4090FD50E238070d",
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM").foreach(check)
    }
  }
}
