require "./src/crystal-ecc-constant"
Crystal::Ecc::Constant::Sodium.init
kp1 = Crystal::Ecc::Constant::Ed25519KeyPair.generate
kp2 = kp1
kp1.dispose
kp2.dispose
