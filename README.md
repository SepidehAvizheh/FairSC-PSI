The project contains a proof-of-concept implementation of the smart contract (SC) in two smart contract-based fair private set intersection protocols, namely SCPSIEC and SCPSI2EC. The smart contracts and the required cryptographic primitives have been written in solidity language.  The CryptoLib.sol library in solidity contains functions for cryptographic primitives including Elliptic curve variant of Pedersen commitment, the Elgamal encryption, Zero-knowledge proof of knowledge for correct re-encryption,  Zero-knowledge proof of knowledge for known plaintext, Merkle proof verification, etc. The zero-knowledge proofs are based on non-interactive Sigma protocols with Fiat-Shamir heuristic. All the cryptographic primitives are run over Elliptic curve $Secp256k1$  which has been implemented by EllipticCurve .sol, EllipticCurveInterface.sol, and SafeMath.sol contracts  (ref: https://github.com/18dew/solGrined/blob/master/contracts/). sharedStruct.sol defines the data structures that are commonly used by the abovementioned contracts.