function CosmosBufferToPublic(pubBuf, hrp = "cosmos") {
  const Buffer = libs.buffer.Buffer;
  const AminoSecp256k1PubkeyPrefix = Buffer.from("EB5AE987", "hex");
  const AminoSecp256k1PubkeyLength = Buffer.from("21", "hex");
  pubBuf = Buffer.concat([
    AminoSecp256k1PubkeyPrefix,
    AminoSecp256k1PubkeyLength,
    pubBuf,
  ]);
  return libs.bech32.encode(`${hrp}pub`, libs.bech32.toWords(pubBuf));
}

function CosmosBufferToAddress(pubBuf, hrp = "cosmos") {
  const sha256_ed = libs.createHash("sha256").update(pubBuf).digest();
  const ripemd160_ed = libs.createHash("rmd160").update(sha256_ed).digest();
  return libs.bech32.encode(hrp, libs.bech32.toWords(ripemd160_ed));
}

// Ethermint-style address generation (used by AIOZ, Evmos, Injective, etc.)
// Uses keccak256 hash of uncompressed public key (Ethereum-style)
function EthermintBufferToAddress(pubBuf, hrp = "aioz") {
  // Get uncompressed public key from compressed public key
  var ethPubkey = libs.ethUtil.importPublic(pubBuf);
  // Get Ethereum-style address (keccak256 of pubkey, last 20 bytes)
  var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
  // Encode with bech32
  return libs.bech32.encode(hrp, libs.bech32.toWords(addressBuffer));
}

function EthermintBufferToHexAddress(pubBuf) {
  var ethPubkey = libs.ethUtil.importPublic(pubBuf);
  var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
  var hexAddress = addressBuffer.toString("hex");
  var checksumAddress = libs.ethUtil.toChecksumAddress(hexAddress);
  return libs.ethUtil.addHexPrefix(checksumAddress);
}
