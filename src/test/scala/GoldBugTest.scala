import org.scalatest.FunSpec
import gold.bug.secp256k1.PublicKey
import gold.bug.secp256k1.PrivateKey

class GoldBugTest extends FunSpec {
  describe("PublicKey From Known PrivateKey") {
    it("Should default to outputting compressed keys") {
      assert("0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
        == PrivateKey
        .fromString("c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")
        .getPublicKey
        .toString)
    }
    it("Should handle optionally outputting an uncompressed key") {
      assert("0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
        == PrivateKey
        .fromString("c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c")
        .getPublicKey
        .toString(compressed = false))
    }
  }
}