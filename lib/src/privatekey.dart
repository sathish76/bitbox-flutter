import 'package:bitbox/src/publickey.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'dart:typed_data';
import 'dart:math';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

/// Manages an ECDSA private key.
///
/// Bitcoin uses ECDSA for it's public/private key cryptography.
/// Specifically it uses the `secp256k1` elliptic curve.
///
/// This class wraps cryptographic operations related to ECDSA from the
/// [PointyCastle](https://pub.dev/packages/pointycastle) library/package.
///
/// You can read a good primer on Elliptic Curve Cryptography at [This Cloudflare blog post](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/)
///
///
class BCHPrivateKey {
  final _domainParams = ECDomainParameters('secp256k1');
  final _secureRandom = FortunaRandom();

  var _hasCompressedPubKey = false;
  var _networkType = 0; //Mainnet by default

  var random = Random.secure();

  BigInt _d;
  ECPrivateKey _ecPrivateKey;
  BCHPublicKey _bchPublicKey;

  /// Constructs a  random private key.
  ///
  /// [networkType] - Optional network type. Defaults to mainnet. The network type is only
  /// used when serialising the Private Key in *WIF* format. See [toWIF()].
  ///
  BCHPrivateKey({networkType = 0}) {
    var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());
    _secureRandom.seed(KeyParameter(_seed()));

    var generator = ECKeyGenerator();
    generator.init(ParametersWithRandom(keyParams, _secureRandom));

    var retry =
        100; //100 retries to get correct bitLength. Problem in PointyCastle lib ?
    AsymmetricKeyPair keypair;
    while (retry > 0) {
      keypair = generator.generateKeyPair();
      ECPrivateKey key = keypair.privateKey as ECPrivateKey;
      if (key.d.bitLength == 256) {
        break;
      } else {
        retry--;
      }
    }

    _hasCompressedPubKey = true;
    _networkType = networkType;
    _ecPrivateKey = keypair.privateKey as ECPrivateKey;
    _d = _ecPrivateKey.d;

    if (_d.bitLength != 256) {
      throw Exception(
          "Failed to generate a valid private key after 100 tries. Try again. ");
    }

    _bchPublicKey = BCHPublicKey.fromPrivateKey(this);
  }

  /// Construct a  Private Key from the hexadecimal value representing the
  /// BigInt value of (d) in ` Q = d * G `
  ///
  /// [privhex] - The BigInt representation of the private key as a hexadecimal string
  ///
  /// [networkType] - The network type we intend to use to corresponding WIF representation on.
  BCHPrivateKey.fromHex(String privhex) {
    var d = BigInt.parse(privhex, radix: 16);

    _hasCompressedPubKey = true;
    _networkType = 0;
    _ecPrivateKey = _privateKeyFromBigInt(d);
    _d = d;
    _bchPublicKey = BCHPublicKey.fromPrivateKey(this);
  }

  /// Returns the *naked* private key Big Integer value as a hexadecimal string
  String toHex() {
    return _d.toRadixString(16);
  }

  Uint8List _seed() {
    var random = Random.secure();
    var seed = List<int>.generate(32, (_) => random.nextInt(256));
    return Uint8List.fromList(seed);
  }

  ECPrivateKey _privateKeyFromBigInt(BigInt d) {
    if (d == BigInt.zero) {
      throw Exception(
          'Zero is a bad value for a private key. Pick something else.');
    }

    return ECPrivateKey(d, _domainParams);
  }

  /// Returns the *naked* private key Big Integer value as a Big Integer
  BigInt get privateKey {
    return _d;
  }

  /// Returns the [BCHPublicKey] corresponding to this ECDSA private key.
  ///
  /// NOTE: `Q = d * G` where *Q* is the public key, *d* is the private key and `G` is the curve's Generator.
  BCHPublicKey get publicKey {
    return _bchPublicKey;
  }

  /// Returns true if the corresponding public key for this private key
  /// is in *compressed* format. To read more about compressed public keys see [BCHPublicKey().getEncoded()]
  bool get isCompressed {
    return _hasCompressedPubKey;
  }
}
