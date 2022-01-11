import 'dart:typed_data';
import 'dart:convert';
import '../../bitbox.dart';

Uint8List magicHash(String message) {
  Uint8List messagePrefix =
      Uint8List.fromList(utf8.encode('\x18Bitcoin Signed Message:\n'));
  int messageVISize = encodingLength(message.length);
  int length = messagePrefix.length + messageVISize + message.length;
  Uint8List buffer = new Uint8List(length);
  buffer.setRange(0, messagePrefix.length, messagePrefix);
  encode(message.length, buffer, messagePrefix.length);
  buffer.setRange(
      messagePrefix.length + messageVISize, length, utf8.encode(message));
  return Crypto.hash256(buffer);
}
