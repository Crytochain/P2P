/**
 * @description 创建钱包
 * @return { address: '*****',secret: '******'} 
 */
const Wallet = require('./tool/lbr-account')

var w = Wallet.generate()
let lbrAccount = { address: w.getAddressString(), secret: w.getPrivateKeyString() };
console.log(lbrAccount)
