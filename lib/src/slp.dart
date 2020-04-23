import 'dart:convert';
import 'dart:typed_data';
import 'package:bitbox/bitbox.dart';
import 'package:hex/hex.dart';
import 'package:http/http.dart';
import 'package:slp_mdm/slp_mdm.dart';
import 'package:slp_parser/slp_parser.dart';
import 'dart:math' as math;

class SLP {
  getTokenInformation(String tokenID, [bool decimalConversion = false]) async {
    Response response;
    var res;
    try {
      response =
          await RawTransactions.getRawtransaction(tokenID, verbose: true);
      res = jsonDecode(response.body);
      if (res.containsKey('error')) {
        throw Exception(
            "BITBOX response error for 'RawTransactions.getRawTransaction'");
      }
    } catch (e) {
      throw Exception(e);
    }
    var slpMsg =
        parseSLP(HEX.decode(res['vout'][0]['scriptPubKey']['hex'])).toMap();
    if (decimalConversion) {
      Map slpMsgData = slpMsg['data'];

      if (slpMsg['transactionType'] == "GENESIS" ||
          slpMsg['transactionType'] == "MINT") {
        slpMsgData['qty'] =
            slpMsgData['qty'] / math.pow(10, slpMsgData['decimals']);
      } else {
        slpMsgData['amounts']
            .map((o) => o / math.pow(10, slpMsgData['decimals']));
      }
    }

    if (slpMsg['transactionType'] == "GENESIS") {
      slpMsg['tokenIdHex'] = tokenID;
    }
    return slpMsg;
  }

  mapToSLPUtxoArray(List utxos, String xpriv) {
    List utxo = [];
    utxos.forEach((txo) => utxo.add({
          'satoshis': new BigInt.from(txo['satoshis']),
          'xpriv': xpriv,
          'txid': txo['txid'],
          'vout': txo['vout'],
          'slpTransactionDetails': txo['slpTransactionDetails'],
          'slpUtxoJudgement': txo['slpUtxoJudgement'],
          'slpUtxoJudgementAmount': txo['slpUtxoJudgementAmount'],
        }));
    return utxo;
  }

  simpleTokenSend(
      {String tokenId,
      double sendAmount,
      List inputUtxos,
      String tokenReceiverAddress,
      String changeReceiverAddress,
      List requiredNonTokenOutputs,
      int extraFee,
      int type = 0x01}) async {
    BigInt amount;
    if (tokenId is! String) {
      return Exception("Token id should be a String");
    }
    if (tokenReceiverAddress is! String) {
      throw new Exception("Token address should be a String");
    }
    try {
      if (sendAmount > 0) {
        amount = BigInt.from(sendAmount);
      }
    } catch (e) {
      return Exception("Invalid amount");
    }

    // 1 Set the token send amounts, send tokens to a
    // new receiver and send token change back to the sender
    BigInt totalTokenInputAmount = BigInt.from(0);
    inputUtxos.forEach((txo) =>
        totalTokenInputAmount += _preSendSlpJudgementCheck(txo, tokenId));

    // 2 Compute the token Change amount.
    BigInt tokenChangeAmount = totalTokenInputAmount - amount;
    bool sendChange = tokenChangeAmount > new BigInt.from(0);

    String txHex;
    if (tokenChangeAmount < new BigInt.from(0)) {
      return throw Exception('Token inputs less than the token outputs');
    }
    // 3 Create the Send OP_RETURN message
    var sendOpReturn = Send(
        HEX.decode(tokenId),
        tokenChangeAmount > BigInt.from(0)
            ? [amount, tokenChangeAmount]
            : [amount]);
    // 4 Create the raw Send transaction hex
    txHex = await _buildRawSendTx(
        slpSendOpReturn: sendOpReturn,
        inputTokenUtxos: inputUtxos,
        tokenReceiverAddresses: sendChange
            ? [tokenReceiverAddress, changeReceiverAddress]
            : [tokenReceiverAddress],
        bchChangeReceiverAddress: changeReceiverAddress,
        requiredNonTokenOutputs: requiredNonTokenOutputs,
        extraFee: extraFee);

    // Return raw hex for this transaction
    return txHex;
  }

  BigInt _preSendSlpJudgementCheck(Map txo, tokenID) {
    if (txo['slpUtxoJudgement'] == "undefined" ||
        txo['slpUtxoJudgement'] == null ||
        txo['slpUtxoJudgement'] == "UNKNOWN") {
      throw Exception(
          "There is at least one input UTXO that does not have a proper SLP judgement");
    }
    if (txo['slpUtxoJudgement'] == "UNSUPPORTED_TYPE") {
      throw Exception(
          "There is at least one input UTXO that is an Unsupported SLP type.");
    }
    if (txo['slpUtxoJudgement'] == "SLP_BATON") {
      throw Exception(
          "There is at least one input UTXO that is a baton. You can only spend batons in a MINT transaction.");
    }
    if (txo.containsKey('slpTransactionDetails')) {
      if (txo['slpUtxoJudgement'] == "SLP_TOKEN") {
        if (!txo.containsKey('slpUtxoJudgementAmount')) {
          throw Exception(
              "There is at least one input token that does not have the 'slpUtxoJudgementAmount' property set.");
        }
        if (txo['slpTransactionDetails']['tokenIdHex'] != tokenID) {
          throw Exception(
              "There is at least one input UTXO that is a different SLP token than the one specified.");
        }
        if (txo['slpTransactionDetails']['tokenIdHex'] == tokenID) {
          return BigInt.from(double.parse(txo['slpUtxoJudgementAmount']));
        }
      }
    }
    return BigInt.from(0);
  }

  _buildRawSendTx(
      {List<int> slpSendOpReturn,
      List inputTokenUtxos,
      List tokenReceiverAddresses,
      String bchChangeReceiverAddress,
      List requiredNonTokenOutputs,
      int extraFee,
      type = 0x01}) async {
    // Check proper address formats are given
    tokenReceiverAddresses.forEach((addr) {
      if (!addr.startsWith('simpleledger:')) {
        throw new Exception("Token receiver address not in SlpAddr format.");
      }
    });

    if (bchChangeReceiverAddress != null) {
      if (!bchChangeReceiverAddress.startsWith('simpleledger:')) {
        throw new Exception(
            "BCH/SLP token change receiver address is not in SlpAddr format.");
      }
    }

    // Parse the SLP SEND OP_RETURN message
    var sendMsg = parseSLP(slpSendOpReturn).toMap();
    Map sendMsgData = sendMsg['data'];

    // Make sure we're not spending inputs from any other token or baton
    var tokenInputQty = new BigInt.from(0);
    inputTokenUtxos.forEach((txo) {
      if (txo['slpUtxoJudgement'] == "NOT_SLP") {
        return;
      }
      if (txo['slpUtxoJudgement'] == "SLP_TOKEN") {
        if (txo['slpTransactionDetails']['tokenIdHex'] !=
            sendMsgData['tokenId']) {
          throw Exception("Input UTXOs included a token for another tokenId.");
        }
        tokenInputQty +=
            BigInt.from(double.parse(txo['slpUtxoJudgementAmount']));
        return;
      }
      if (txo['slpUtxoJudgement'] == "SLP_BATON") {
        throw Exception("Cannot spend a minting baton.");
      }
      if (txo['slpUtxoJudgement'] == ['INVALID_TOKEN_DAG'] ||
          txo['slpUtxoJudgement'] == "INVALID_BATON_DAG") {
        throw Exception("Cannot currently spend UTXOs with invalid DAGs.");
      }
      throw Exception("Cannot spend utxo with no SLP judgement.");
    });

    // Make sure the number of output receivers
    // matches the outputs in the OP_RETURN message.
    if (tokenReceiverAddresses.length != sendMsgData['amounts'].length) {
      throw Exception(
          "Number of token receivers in config does not match the OP_RETURN outputs");
    }

    // Make sure token inputs == token outputs
    var outputTokenQty = BigInt.from(0);
    sendMsgData['amounts'].forEach((a) => outputTokenQty += a);
    if (tokenInputQty != outputTokenQty) {
      throw Exception("Token input quantity does not match token outputs.");
    }

    // Create a transaction builder
    var transactionBuilder = Bitbox.transactionBuilder();
    //  let sequence = 0xffffffff - 1;

    // Calculate the total input amount & add all inputs to the transaction

    var inputSatoshis = BigInt.from(0);
    inputTokenUtxos.forEach((i) {
      inputSatoshis += i['satoshis'];
      transactionBuilder.addInput(i['txid'], i['vout']);
    });

    // Calculate the amount of outputs set aside for special BCH-only outputs for fee calculation
    var bchOnlyCount =
        requiredNonTokenOutputs != null ? requiredNonTokenOutputs.length : 0;
    BigInt bchOnlyOutputSatoshis = BigInt.from(0);
    requiredNonTokenOutputs != null
        ? requiredNonTokenOutputs
            .forEach((o) => bchOnlyOutputSatoshis += BigInt.from(o['satoshis']))
        : bchOnlyOutputSatoshis = bchOnlyOutputSatoshis;

    // Calculate mining fee cost
    int sendCost = _calculateSendCost(slpSendOpReturn.length,
        inputTokenUtxos.length, tokenReceiverAddresses.length + bchOnlyCount,
        bchChangeAddress: bchChangeReceiverAddress,
        feeRate: extraFee != null ? extraFee : 1);

    // Compute BCH change amount
    BigInt bchChangeAfterFeeSatoshis =
        inputSatoshis - BigInt.from(sendCost) - bchOnlyOutputSatoshis;

    // Start adding outputs to transaction
    // Add SLP SEND OP_RETURN message
    transactionBuilder.addOutput(compile(slpSendOpReturn), 0);

    // Add dust outputs associated with tokens
    tokenReceiverAddresses.forEach((outputAddress) {
      outputAddress = Address.toLegacyAddress(outputAddress);
      outputAddress = Address.toCashAddress(outputAddress);
      transactionBuilder.addOutput(outputAddress, 546);
    });

    // Add BCH-only outputs
    var outputAddress;
    if (requiredNonTokenOutputs != null) {
      if (requiredNonTokenOutputs.length > 0) {
        requiredNonTokenOutputs.forEach((output) {
          outputAddress = Address.toLegacyAddress(output.receiverAddress);
          outputAddress = Address.toCashAddress(outputAddress);
          transactionBuilder.addOutput(outputAddress, output.satoshis);
        });
      }
    }

    // Add change, if any
    if (bchChangeAfterFeeSatoshis > new BigInt.from(546)) {
      var legacyaddr = Address.toLegacyAddress(bchChangeReceiverAddress);
      var cashaddr = Address.toCashAddress(legacyaddr);
      transactionBuilder.addOutput(cashaddr, bchChangeAfterFeeSatoshis.toInt());
    }

    // Sign txn and add sig to p2pkh input with xpriv,
    var inp = 0;
    inputTokenUtxos.forEach((i) {
      if (!i.containsKey('xpriv')) {
        return throw Exception("Input doesnt contain a xpriv");
      }
      ECPair paymentKeyPair = HDNode.fromXPriv(i['xpriv']).keyPair;
      transactionBuilder.sign(
          inp, paymentKeyPair, i['satoshis'].toInt(), Transaction.SIGHASH_ALL);
      inp++;
    });

    // Build the transaction to hex and return
    // warn user if the transaction was not fully signed
    String hex = transactionBuilder.build().toHex();

    // Check For Low Fee
    int outValue = 0;
    transactionBuilder.tx.outputs.forEach((o) => outValue += o.value);
    int inValue = 0;
    inputTokenUtxos.forEach((i) => inValue += i['satoshis'].toInt());
    if (inValue - outValue < hex.length / 2) {
      print('inValue: $inValue');
      print('outValue: $outValue');
      print('hex: $hex');
      throw Exception(
          "Transaction input BCH amount is too low.  Add more BCH inputs to fund this transaction.");
    }
    return hex;
  }

  int _calculateSendCost(int sendOpReturnLength, int inputUtxoSize, int outputs,
      {String bchChangeAddress, int feeRate = 1, bool forTokens = true}) {
    int nonfeeoutputs = 0;
    if (forTokens) {
      nonfeeoutputs = outputs * 546;
    }
    if (bchChangeAddress != null && bchChangeAddress != 'undefined') {
      outputs += 1;
    }

    int fee = BitcoinCash.getByteCount(inputUtxoSize, outputs);
    fee += sendOpReturnLength;
    fee += 10; // added to account for OP_RETURN ammount of 0000000000000000
    fee *= feeRate;
    //print("SEND cost before outputs: " + fee.toString());
    fee += nonfeeoutputs;
    //print("SEND cost after outputs are added: " + fee.toString());
    return fee;
  }

  /*
    Todo
   */

  _createSimpleToken(
      {String tokenName,
      String tokenTicker,
      int tokenAmount,
      String documentUri,
      Uint8List documentHash,
      int decimals,
      String tokenReceiverAddress,
      String batonReceiverAddress,
      String bchChangeReceiverAddress,
      List inputUtxos,
      int type = 0x01}) async {
    int batonVout = batonReceiverAddress.isNotEmpty ? 2 : null;
    if (decimals == null) {
      throw Exception("Decimals property must be in range 0 to 9");
    }
    if (tokenTicker != null && tokenTicker is! String) {
      throw Exception("ticker must be a string");
    }
    if (tokenName != null && tokenName is! String) {
      throw Exception("name must be a string");
    }

    var genesisOpReturn = Genesis(tokenTicker, tokenName, documentUri,
        documentHash, decimals, BigInt.from(batonVout), tokenAmount);
    if (genesisOpReturn.length > 223) {
      throw Exception(
          "Script too long, must be less than or equal to 223 bytes.");
    }
    return genesisOpReturn;

    // var genesisTxHex = buildRawGenesisTx({
    //   slpGenesisOpReturn: genesisOpReturn,
    //   mintReceiverAddress: tokenReceiverAddress,
    //   batonReceiverAddress: batonReceiverAddress,
    //   bchChangeReceiverAddress: bchChangeReceiverAddress,
    //   input_utxos: Utils.mapToUtxoArray(inputUtxos)
    // });

    // return await RawTransactions.sendRawTransaction(genesisTxHex);
  }

  //simpleTokenMint() {}

  //simpleTokenBurn() {}
}
