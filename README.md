GoldBug Cryptographic Library
-----------------------------

> ...If you do not take it up with you in some way, I shall be under the necessity of breaking your head with this shovel
>
> ― Edgar Allan Poe, ***The Gold Bug***

GoldBug is a Scala cryptographic library.  It ultimately aims to provide an isomorphic Scala/ScalaJS interface to cryptographic primitives commonly used in cryptocurrency.

GoldBug is based on BitPay's [BitAuth](https://github.com/bitpay/bitauth) and the [Clojure(Script) port](https://github.com/Sepia-Officinalis/clj-bitauth).  As such it employs the same ECDSA signature strategy as those libraries, and has been tested to ensure interoperability with signatures produced by those libraries.