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

  getUtxos(String address) async {
    // must be a cash addr
    var res;
    try {
      Address.toLegacyAddress(address);
    } catch (_) {
      throw new Exception(
          "Not an a valid address format, must be cashAddr or Legacy address format.");
    }
    res = await Address.utxo(address) as List<Utxo>;
    return res;
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
      List<String> tokenReceiverAddresseses,
      String changeReceiverAddress,
      List requiredNonTokenOutputs,
      int extraFee = 0,
      int type = 0x01}) async {
    BigInt amount;
    if (tokenId is! String) {
      return Exception("Token id should be a String");
    }
    tokenReceiverAddresseses.forEach((addr) {
      if (addr is! String) {
        throw new Exception("Token id should be a String");
      }
    });
    try {
      if (sendAmount > 0) {
        amount = BigInt.from(sendAmount);
      }
    } catch (e) {
      return Exception("Invalid amount");
    }

    // 1 Set the token send amounts, we'll send 100 tokens to a
    //    new receiver and send token change back to the sender
    BigInt totalTokenInputAmount = BigInt.from(0);
    inputUtxos.forEach((txo) =>
        totalTokenInputAmount += preSendSlpJudgementCheck(txo, tokenId));

    // 2 Compute the token Change amount.
    BigInt tokenChangeAmount = totalTokenInputAmount - amount;

    String txHex;
    if (tokenChangeAmount > new BigInt.from(0)) {
      // 3 Create the Send OP_RETURN message
      var sendOpReturn = Send(HEX.decode(tokenId), [amount, tokenChangeAmount]);
      // 4 Create the raw Send transaction hex
      txHex = await buildRawSendTx(
          slpSendOpReturn: sendOpReturn,
          inputTokenUtxos: inputUtxos,
          tokenReceiverAddress: tokenReceiverAddresseses,
          bchChangeReceiverAddress: changeReceiverAddress,
          requiredNonTokenOutputs: requiredNonTokenOutputs,
          extraFee: extraFee);
    } else if (tokenChangeAmount == new BigInt.from(0)) {
      // 3 Create the Send OP_RETURN message
      var sendOpReturn = Send(HEX.decode(tokenId), [amount]);
      // 4 Create the raw Send transaction hex
      txHex = await buildRawSendTx(
          slpSendOpReturn: sendOpReturn,
          inputTokenUtxos: inputUtxos,
          tokenReceiverAddress: tokenReceiverAddresseses,
          bchChangeReceiverAddress: null,
          requiredNonTokenOutputs: requiredNonTokenOutputs,
          extraFee: extraFee);
    } else {
      throw Exception('Token inputs less than the token outputs');
    }
    // Return raw hex for this transaction
    return txHex;
  }

  BigInt preSendSlpJudgementCheck(Map txo, tokenID) {
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

  buildRawSendTx(
      {List<int> slpSendOpReturn,
      List inputTokenUtxos,
      List tokenReceiverAddress,
      String bchChangeReceiverAddress,
      List requiredNonTokenOutputs,
      int extraFee,
      type = 0x01}) async {
    // Check proper address formats are given
    tokenReceiverAddress.forEach((addr) {
      if (!addr.startsWith('simpleledger:')) {
        throw new Exception("Token receiver address not in SlpAddr format.");
      }
    });

    if (bchChangeReceiverAddress != null) {
      if (!bchChangeReceiverAddress.startsWith('simpleledger:')) {
        throw new Exception(
            "Token/BCH change receiver address is not in SLP format.");
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
    var chgAddr = bchChangeReceiverAddress == null ? 0 : 1;
    if (!sendMsgData.containsKey('amounts')) {
      throw Exception("OP_RETURN contains no SLP send outputs.");
    }
    if (tokenReceiverAddress.length + chgAddr !=
        sendMsgData['amounts'].length) {
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
    BigInt bcOnlyOutputSatoshis = BigInt.from(0);
    requiredNonTokenOutputs != null
        ? requiredNonTokenOutputs
            .forEach((o) => bcOnlyOutputSatoshis += BigInt.from(o['satoshis']))
        : bcOnlyOutputSatoshis = bcOnlyOutputSatoshis;

    // Calculate mining fee cost
    int sendCost = calculateSendCost(slpSendOpReturn.length,
        inputTokenUtxos.length, tokenReceiverAddress.length + bchOnlyCount,
        bchChangeAddress: bchChangeReceiverAddress,
        feeRate: extraFee != null ? extraFee : 0);

    // Compute BCH change amount
    BigInt bchChangeAfterFeeSatoshis =
        inputSatoshis - BigInt.from(sendCost) - bcOnlyOutputSatoshis;

    // Start adding outputs to transaction
    // Add SLP SEND OP_RETURN message
    transactionBuilder.addOutput(compile(slpSendOpReturn), 0);

    // Add dust outputs associated with tokens
    tokenReceiverAddress.forEach((outputAddress) {
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
      bchChangeReceiverAddress =
          Address.toLegacyAddress(bchChangeReceiverAddress);
      bchChangeReceiverAddress =
          Address.toCashAddress(bchChangeReceiverAddress);
      transactionBuilder.addOutput(
          bchChangeReceiverAddress, bchChangeAfterFeeSatoshis.toInt());
    }

    // Sign txn and add sig to p2pkh input for convenience if wif is provided,
    // otherwise skip signing.
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
      throw Exception(
          "Transaction input BCH amount is too low.  Add more BCH inputs to fund this transaction.");
    }
    var txid = await RawTransactions.sendRawTransaction(hex);
    return txid;
  }

  int calculateSendCost(int sendOpReturnLength, int inputUtxoSize, int outputs,
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

  createSimpleToken(
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