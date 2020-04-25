/**
 * @description 转账
 */
const { transferERC20 } = require('./tool/lbr-transfer')

let config = {
    vnodeUri: ["http://47.52.244.142:8087/vnode", "http://47.52.244.142:8087/vnode1"], // Array     vnode节点地址
    scsUri: ["http://47.52.244.142:8087/scs", "http://47.52.244.142:8087/scs1"], // Array       scs节点地址
    vnodeVia: ["0x3fcf472dbe032e85227c0061824a10e5627b0274", "0xc0eab6c0f010c31887c7a2e5f62c16bd372842af"], // Array        收益地址
    LBRChain: "0x36aa307a4157653eafa47f327b11963ccf174ed4", // String       LBR链地址
    netWork: 99, // Number      99：主网，101：测试网
    timeOut: 10 // Number 超时时间
}

var lbrAccount = { // lbr钱包
    address: "",
    secret: ""
}

var toAddress = "0x6b4fb976c0a79c2ab5498a1a61e5c25892e74087" // 转账对家钱包
var tokenCfg = {
    tokenAdd: "0x1652a76c60a73467109527dfa06d306ddb01aa89", // token地址
    decimal: 18, // 转账Token精度
    amount: 0.12 // 转账金额
}

var logs = "转账Demo" // 转账备注

transfer()

/**
 * @description 转账
 * @returns 
 * {
 * result: 'success', // 返回结果, success: 转账成功，error:转账失败
 * hash: '0x0782bcae756f2b7c79efe3a22a7d5f69bcfc95994b9faf3844eabaf592177487' // 转账hash
 * }
 */
async function transfer() {
    let res = await transferERC20(lbrAccount, toAddress, tokenCfg.tokenAdd, tokenCfg.amount, tokenCfg.decimal, logs, config);
    console.log(res)
}
