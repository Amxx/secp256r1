const { ethers } = require('ethers');
const { secp256r1 } = require('@noble/curves/p256');

const prepareSignature = (
  privateKey = secp256r1.utils.randomPrivateKey(),
  messageHash = ethers.hexlify(ethers.randomBytes(32))
) => {
  const publicKey = [
    secp256r1.getPublicKey(privateKey, false).slice(0x01, 0x21),
    secp256r1.getPublicKey(privateKey, false).slice(0x21, 0x41),
  ].map(ethers.hexlify)
  const { r, s, recovery } = secp256r1.sign(messageHash.replace(/0x/, ''), privateKey);
  const signature = [ r, s ].map(v => ethers.toBeHex(v, 32));
  return { privateKey, publicKey, signature, recovery, messageHash };
};

module.exports = { prepareSignature };