import 'dart:convert';
import 'dart:typed_data';

import 'package:bitbox/bitbox.dart';
import 'package:bitbox/src/utils/magic_hash.dart';

import 'utils/bip21.dart';

/// Bitcoin Cash specific utilities
class BitcoinCash {
  /// Converts Bitcoin Cash units to satoshi units
  static int toSatoshi(double bchAmount) {
    return (bchAmount * 100000000).round();
  }

  /// Converts satoshi units to Bitcoin Cash units
  static double fromSatoshi(int satoshi) {
    return satoshi / 100000000;
  }

  // Calculates and returns byte count of a transaction
  static int getByteCount(int inputs, int outputs) {
    return ((inputs * 148 * 4 + 34 * 4 * outputs + 10 * 4) / 4).ceil();
  }

  // Converts a [String] bch address and its [Map] options into [String] bip-21 uri
  static String encodeBIP21(String address, Map<String, dynamic> options) {
    return Bip21.encode(address, options);
  }

  // Converts [String] bip-21 uri into a [Map] of bch address and its options
  static Map<String, dynamic> decodeBIP21(String uri) {
    return Bip21.decode(uri);
  }

  // Sign a string message with privateKey in Bitcoin Signature format
  static Uint8List signMessage(String message, [returnString = false]) {
    Uint8List signatureBuffer = magicHash(message);
    //return utf8.decode(signatureBuffer);
    return signatureBuffer;
  }

  static Uint8List? getOpReturnScript(String data) {
    return compile([Opcodes.OP_RETURN, utf8.encode(data)]);
  }
}
