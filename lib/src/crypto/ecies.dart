import 'dart:convert';
import 'dart:typed_data';
import 'package:bitbox/src/privatekey.dart';
import 'package:bitbox/src/publickey.dart';
import 'package:collection/collection.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';

/// A Class for performing Elliptic Curve Integrated Encryption Scheme operations.
///
/// This class only makes provision for the "Electrum ECIES" aka "BIE1" serialization
/// format for the cipherText.
class Ecies {
  static final ECDomainParameters _domainParams =
      ECDomainParameters('secp256k1');
  static final SHA256Digest _sha256Digest = SHA256Digest();
  static final _tagLength = 32; //size of hmac

  /// Perform an ECIES encryption using AES for the symmetric cipher.
  ///
  /// [messageBuffer] - The buffer to encrypt. Note that the buffer in this instance has a very specific
  /// encoding format called "BIE1" or "Electrum ECIES". It is in essence a serialization format with a
  /// built-in checksum.
  ///   - bytes [0 - 4] : Magic value. Literally "BIE1".
  ///   - bytes [4 - 37] : Compressed Public Key
  ///   - bytes [37 - (length - 32) ] : Actual cipherText
  ///   - bytes [ length - 32 ] : (last 32 bytes) Checksum value
  ///
  /// [senderPrivateKey] - Private Key of the sending party
  ///
  /// [recipientPublicKey] - Public Key of the party who can decrypt the message
  ///
  static String encryptData(
      {required String message,
      required String senderPrivateKeyHex,
      required String recipientPublicKeyHex,
      String magicValue = "BIE1"}) {
    //Encryption requires derivation of a cipher using the other party's Public Key
    // Bob is sender, Alice is recipient of encrypted message
    // Qb = k o Qa, where
    //     Qb = Bob's Public Key;
    //     k = Bob's private key;
    //     Qa = Alice's public key;

    BCHPrivateKey senderPrivateKey = BCHPrivateKey.fromHex(senderPrivateKeyHex);
    BCHPublicKey recipientPublicKey =
        BCHPublicKey.fromHex(recipientPublicKeyHex);

    List<int> messageBuffer = Uint8List.fromList(message.codeUnits);

    final ECPoint S = (recipientPublicKey.point! *
        senderPrivateKey.privateKey)!; //point multiplication

    final pubkeyS = BCHPublicKey.fromXY(S.x!.toBigInteger()!, S.y!.toBigInteger()!);
    final pubkeyBuffer = HEX.decode(pubkeyS.getEncoded(true));
    final pubkeyHash = SHA512Digest().process(pubkeyBuffer as Uint8List);

    //initialization vector parameters
    final iv = pubkeyHash.sublist(0, 16);
    final kE = pubkeyHash.sublist(16, 32);
    final kM = pubkeyHash.sublist(32, 64);

    CipherParameters params = PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(kE), iv), null);
    BlockCipher encryptionCipher = PaddedBlockCipher('AES/CBC/PKCS7');
    encryptionCipher.init(true, params);

    final cipherText = encryptionCipher.process(messageBuffer as Uint8List);

    final magic = utf8.encode(magicValue);

    final encodedBuffer = Uint8List.fromList(
        magic + HEX.decode(senderPrivateKey.publicKey!.toHex()) + cipherText);

    //calc checksum
    final hmac = _calculateHmac(kM, encodedBuffer);

    return HEX.encode(encodedBuffer + hmac);
  }

  static Uint8List _calculateHmac(Uint8List kM, Uint8List encodedBuffer) {
    final sha256Hmac = HMac(_sha256Digest, 64);
    sha256Hmac.init(KeyParameter(kM));
    final calculatedChecksum = sha256Hmac.process(encodedBuffer);
    return calculatedChecksum;
  }

  /// Perform an ECIES decryption using AES for the symmetric cipher.
  ///
  /// [cipherText] -  The buffer to decrypt. Note that the buffer in this instance has a very specific
  /// encoding format called "BIE1" or "Electrum ECIES". It is in essence a serialization format with a
  /// built-in checksum.
  ///   - bytes [0 - 4] : Magic value. Literally "BIE1".
  ///   - bytes [4 - 37] : Compressed Public Key
  ///   - bytes [37 - (length - 32) ] : Actual cipherText
  ///   - bytes [ length - 32 ] : (last 32 bytes) Checksum valu
  ///
  /// [recipientPrivateKey] - Private Key of the receiving party
  ///
  static String decryptData(
      {required String cipherTextStr,
      required String recipientPrivateKeyHex,
      String magicValue = "BIE1"}) {
    //AES Cipher is calculated as
    //1) S = recipientPrivateKey o senderPublicKey
    //2) cipher = S.x

    List<int> cipherText = HEX.decode(cipherTextStr);

    BCHPrivateKey recipientPrivateKey =
        BCHPrivateKey.fromHex(recipientPrivateKeyHex);

    if (cipherText.length < 37) {
      throw Exception('Buffer is too small ');
    }

    final magic = utf8.decode(cipherText.sublist(0, 4));

    if (magic != magicValue) {
      throw Exception('Not a $magicValue-encoded buffer');
    }

    final senderPubkeyBuffer = cipherText.sublist(4, 37);
    final senderPublicKey =
        BCHPublicKey.fromHex(HEX.encode(senderPubkeyBuffer));

    //calculate S = recipientPrivateKey o senderPublicKey
    final S = (senderPublicKey.point! *
        recipientPrivateKey.privateKey)!; //point multiplication
    final cipher = S.x;

    if (cipherText.length - _tagLength <= 37) {
      throw Exception(
          'Invalid Checksum detected. Combined sum of Checksum and Message makes no sense');
    }

    //validate the checksum bytes
    final pubkeyS = BCHPublicKey.fromXY(S.x!.toBigInteger()!, S.y!.toBigInteger()!);
    final pubkeyBuffer = HEX.decode(pubkeyS.getEncoded(true));
    final pubkeyHash = SHA512Digest().process(pubkeyBuffer as Uint8List);

    //initialization vector parameters
    final iv = pubkeyHash.sublist(0, 16);
    final kE = pubkeyHash.sublist(16, 32);
    final kM = pubkeyHash.sublist(32, 64);

    final message = Uint8List.fromList(
        cipherText.sublist(0, cipherText.length - _tagLength));

    final Uint8List hmac = _calculateHmac(kM, message);

    final Uint8List messageChecksum =
        cipherText.sublist(cipherText.length - _tagLength, cipherText.length) as Uint8List;

    // ignore: prefer_const_constructors
    if (!ListEquality().equals(messageChecksum, hmac)) {
      throw Exception('HMAC checksum failed to validate');
    }

    //decrypt!
    CipherParameters params = PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(kE), iv), null);
    BlockCipher decryptionCipher = PaddedBlockCipher("AES/CBC/PKCS7");
    decryptionCipher.init(false, params);

    final decrypted = decryptionCipher.process(
        cipherText.sublist(37, cipherText.length - _tagLength) as Uint8List);
    return utf8.decode(decrypted);
  }
}
