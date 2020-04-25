const BigNumber = require('bignumber.js');
const { sha3, toHex, signTransaction } = require('./lbr-utils')
const Coder = require('../solidity/coder')
const axios = require("axios");
const fetch = axios.create({ headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } });

var lbrConfig; // lbr链配置

/**
 * ERC20转账
 * @param fromAccount 发起转账账户
 * @param toAddress 转账目标账户
 * @param tokenAdd 转账Token地址
 * @param amount 转账数量
 * @param tokenDecimal 转账Token精度
 * @param logs 转账备注
 * @param config lbr链配置
 */
exports.transferERC20 = async function (fromAccount, toAddress, tokenAdd, amount, tokenDecimal, logs, config) {
    try {
        lbrConfig = config;
        let data = tokenAdd + sha3('transfer(address,uint256)').substr(2, 8) +
            Coder.encodeParams(['address', 'uint256'], [toAddress, new BigNumber(amount).multipliedBy(10 ** tokenDecimal)])
        let memo = Buffer.from(logs).toString('hex')
        let res = await exports.sendRawTransaction(fromAccount.address, fromAccount.secret, data + memo)
        return res;
    } catch (error) {
        throw error
    }
}

/**
 * 发起交易
 * @param {address} from 发起交易地址
 * @param {string} secret 发起交易地址密钥
 * @param {string} data 交易数据
 */
exports.sendRawTransaction = async function (from, secret, data) {
    try {
        let nonce = await getNonce(lbrConfig.LBRChain, from);
        let tmp = getLBRCfg()
        let rawTx = {
            from: from,
            to: lbrConfig.LBRChain,
            nonce: toHex(nonce),
            gasLimit: toHex("0"),
            gasPrice: toHex("0"),
            value: toHex("0"),
            chainId: toHex(lbrConfig.netWork),
            via: tmp.vnodeVia,
            shardingFlag: "0x1",
            data: data
        };
        let signTx = signTransaction(rawTx, secret);
        let params = JSON.stringify({ "jsonrpc": "2.0", "method": "mc_sendRawTransaction", "params": [signTx], "id": 101 })
        let response = await fetch.post(tmp.vnodeUrl, params);
        let txHash = response.data.result;
        if (txHash) {
            let params = JSON.stringify({ "jsonrpc": "2.0", "method": "scs_getReceiptByHash", "params": [lbrConfig.LBRChain, txHash], "id": 101 })
            let i = 0;
            while (true) {
                i++
                if (i > lbrConfig.timeOut) {
                    return { "result": "error", "hash": txHash };
                } else {
                    let res = await fetch.post(tmp.scsUrl, params);
                    let receipt = res.data.result;
                    if (receipt && !receipt.failed) {
                        return { "result": "success", "hash": txHash };
                    } else if (receipt && receipt.failed) {
                        return { "result": "error", "hash": txHash };
                    }
                }
                await new Promise(resolve => setTimeout(resolve, 2000))
            }
        } else {
            return { "result": "error", "error": response.data.error };
        }
    } catch (error) {
        return { "result": "error", "error": error };
    }
}

/**
 * 获取Nonce
 * @param {*} LBRChain lbr链地址
 * @param {*} address 获取Nonce的地址
 */
function getNonce(LBRChain, address) {
    return new Promise((resolve, reject) => {
        let params = JSON.stringify({ "jsonrpc": "2.0", "method": "scs_getNonce", "params": [LBRChain, address], "id": 101 })
        let tmp = getLBRCfg()
        fetch.post(tmp.scsUrl, params).then(function (response) {
            resolve(response.data.result)
        }).catch(function (error) {
            reject(error);
        });
    });
}

// 随机获取vnode、scs节点地址及收益地址
function getLBRCfg() {
    let vnodeVia;
    let vnodeUrl;
    let scsUrl;
    if (Array.isArray(lbrConfig.scsUri) && lbrConfig.scsUri.length > 0) {
        let random = Math.floor(Math.random() * lbrConfig.scsUri.length)
        vnodeVia = lbrConfig.vnodeVia[random]
        vnodeUrl = lbrConfig.vnodeUri[random]
        scsUrl = lbrConfig.scsUri[random];
    }
    return { vnodeVia: vnodeVia, vnodeUrl: vnodeUrl, scsUrl: scsUrl };
}