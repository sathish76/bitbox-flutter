import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:pointycastle/ecc/api.dart' show ECPoint;
import 'package:pointycastle/ecc/curves/secp256k1.dart';

class ECurve {
  static final secp256k1 = new ECCurve_secp256k1();
  static final n = secp256k1.n;
  static final G = secp256k1.G;
  static final zero32 = Uint8List.fromList(List.generate(32, (index) => 0));
  static final ecGroupOrder = HEX.decode(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  static final ecP = HEX.decode(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

  /// Decode a BigInt from bytes in big-endian encoding.
  static BigInt decodeBigInt(List<int> bytes) {
    var result = BigInt.from(0);
    for (var i = 0; i < bytes.length; i++) {
      result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
    }
    return result;
  }

  /// Encode a BigInt into bytes using big-endian encoding.
  static Uint8List encodeBigInt(BigInt number) {
    var _byteMask = BigInt.from(0xff);
    // Not handling negative numbers. Decide how you want to do that.
    var size = (number.bitLength + 7) >> 3;
    var result = Uint8List(size);
    for (var i = 0; i < size; i++) {
      result[size - i - 1] = (number & _byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  static Uint8List? privateAdd(Uint8List d, Uint8List tweak) {
//    if (!isPrivate(d)) throw new ArgumentError(THROW_BAD_PRIVATE);
//    if (!isOrderScalar(tweak)) throw new ArgumentError(THROW_BAD_TWEAK);
    BigInt dd = decodeBigInt(d);
    BigInt tt = decodeBigInt(tweak);
    Uint8List dt = encodeBigInt((dd + tt) % n);
    if (!isPrivate(dt)) return null;
    return dt;
  }

  static bool isPrivate(Uint8List x) {
    if (!isScalar(x)) return false;
    return _compare(x, zero32) > 0 && // > 0
        _compare(x, ecGroupOrder as Uint8List) < 0; // < G
  }

  static bool isScalar(Uint8List x) {
    return x.length == 32;
  }

  static Uint8List? pointFromScalar(Uint8List d, bool _compressed) {
//    if (!isPrivate(d)) throw new ArgumentError(THROW_BAD_PRIVATE);
    BigInt dd = decodeBigInt(d);
    ECPoint pp = (G * dd)!;
    if (pp.isInfinity) return null;
    return pp.getEncoded(_compressed);
  }

  static Uint8List? pointAddScalar(
      Uint8List p, Uint8List tweak, bool _compressed) {
//    if (!isPoint(p)) throw new ArgumentError(THROW_BAD_POINT);
//    if (!isOrderScalar(tweak)) throw new ArgumentError(THROW_BAD_TWEAK);
    bool compressed = assumeCompression(_compressed, p);
    ECPoint? pp = decodeFrom(p);
    if (_compare(tweak, zero32) == 0) return pp!.getEncoded(compressed);
    BigInt tt = decodeBigInt(tweak);
    ECPoint? qq = G * tt;
    ECPoint uu = (pp! + qq)!;
    if (uu.isInfinity) return null;
    return uu.getEncoded(compressed);
  }

  static int _compare(Uint8List a, Uint8List b) {
    BigInt aa = decodeBigInt(a);
    BigInt bb = decodeBigInt(b);
    if (aa == bb) return 0;
    if (aa > bb) return 1;
    return -1;
  }

  static bool assumeCompression(bool value, Uint8List pubkey) {
    if (value == null && pubkey != null) return _isPointCompressed(pubkey);
    if (value == null) return true;
    return value;
  }

  static bool isPoint(Uint8List p) {
    if (p.length < 33) {
      return false;
    }
    var t = p[0];
    var x = p.sublist(1, 33);

    if (_compare(x, zero32) == 0) {
      return false;
    }
    if (_compare(x, ecP as Uint8List) == 1) {
      return false;
    }
    try {
      decodeFrom(p);
    } catch (err) {
      return false;
    }
    if ((t == 0x02 || t == 0x03) && p.length == 33) {
      return true;
    }
    var y = p.sublist(33);
    if (_compare(y, zero32) == 0) {
      return false;
    }
    if (_compare(y, ecP as Uint8List) == 1) {
      return false;
    }
    if (t == 0x04 && p.length == 65) {
      return true;
    }
    return false;
  }

  static bool _isPointCompressed(Uint8List p) {
    return p[0] != 0x04;
  }

  static ECPoint? decodeFrom(Uint8List P) => secp256k1.curve.decodePoint(P);
}
