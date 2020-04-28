## LBR链转账DEMO及相关解析说明

### 使用

```javascript
npm install
```

### [钱包创建](./src/create-wallet.js)

```javascript
node src/create-wallet.js 
```

### [LBR转账](./src/transfer.js)

```javascript
node src/transfer.js 
```

### LBR链账本解析API说明

- [获取最新区块号](#获取最新区块号)
- [获取指定的区块信息](#获取指定的区块信息)
- [获取指定哈希的交易收据](#获取指定哈希的交易收据)
- [获取指定钱包和NONCE的交易收据](#获取指定钱包和NONCE的交易收据)
- [获取指定交易哈希的交易信息](#获取指定交易哈希的交易信息)
- [获取指定钱包和NONCE的交易信息](#获取指定钱包和NONCE的交易信息)
- [转账数据解析](#转账数据解析)

#### 获取最新区块号

Params
>String - lbr链地址，0x36aa307a4157653eafa47f327b11963ccf174ed4<br>

Returns
>String - 16进制区块号

Example
```
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"scs_getBlockNumber","params":["0x36aa307a4157653eafa47f327b11963ccf174ed4"],"id":101}' 'https://liberumdex.net/scs'

// Result
{
	"jsonrpc": "2.0",
	"id": 101,
	"result": "0xbf869"  // 16进制区块号，10进制为784489
}
```

#### 获取指定的区块信息

Params
>String - lbr链地址，0x36aa307a4157653eafa47f327b11963ccf174ed4<br>
>String - 指定区块高度，只支持16进制数

Returns
>Object - 返回指定区块的区块数据<br>
>extraData：Sting -块额外数据 <br>
>hash：Sting - 区块hash<br>
>miner：Sting - 挖矿奖励的接收账户<br>
>number：Sting - 区块号，16进制<br>
>parentHash：Sting - 上个区块hash<br>
>receiptsRoot：Sting - 块交易收据树的根节点<br>
>stateRoot：Sting - 块最终状态树的根节点<br>
>timestamp：Sting - 时间戳，16进制<br>
>transactions：Array - 区块包含的交易<br>
>transactionsRoot：String - 块中的交易树根节点<br>

Example
```
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"scs_getBlock","params":["0x36aa307a4157653eafa47f327b11963ccf174ed4","0x10"],"id":101}' https://liberumdex.net/scs

// Result
{
	"jsonrpc": "2.0",
	"id": 101,
	"result": {
		"extraData": "0x",
		"hash": "0xb144b0d808c9339a65755ae3c8c3399659c48a1776c264896ff636c85575cd6a",
		"miner": "0x7d4f20dc0712d13c8c2b9b195134938f4940722c",
		"number": "0x10",
		"parentHash": "0xc5ddaf52313bbe0f9c0f3266bb616330c832fd2c02803fcdcf3e0b3515aa5cca",
		"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
		"stateRoot": "0x904896b92203e55e06ef55bbfd6f4741dd793b032179b30ca27c319defa26b79",
		"timestamp": "0x5e243e5e",
		"transactions": [],
		"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	}
}
``` 

#### 获取指定哈希的交易收据

Params
>String - lbr链地址，0x36aa307a4157653eafa47f327b11963ccf174ed4<br>
>String - 交易hash

Returns
>Object - 交易收据
contractAddress: String - 合约地址<br>
failed: Boolean - 交易状态，是否失败，false：交易成功，true：交易失败<br>
logs: Array - 本次交易生成的日志对象数组<br>

  - address: String - 智能合约的地址<br>
  - topics: Array - 智能合约转账过程中相关的转入转出方的地址hash<br>
  - data: String - 智能合约转账的金额（BASE64编码）<br>
  - blockNumber: Number - 区块号<br>
  - transactionHash: String - 交易hash<br>
  - transactionIndex: Number - 交易在区块中的索引位置<br>
  - blockHash: String - 区块hash<br>
  - logIndex: Number - log索引位置<br>
  
logsBloom: String - log过滤器<br>
queryInBlock: Number - 查询区块位置<br>
result: String - 结果<br>

Example
```
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"scs_getReceiptByHash","params":["0x36aa307a4157653eafa47f327b11963ccf174ed4","0x0056a22219c370802fdc5d8bb18d1cc387c97428c6aee95ab794e4e0931e04f5"],"id":101}' https://liberumdex.net/scs

// Result
{
	"jsonrpc": "2.0",
	"id": 101,
	"result": {
		"contractAddress": "0x0000000000000000000000000000000000000000",
		"failed": false,
		"logs": [{
			"address": "0x1652a76c60a73467109527dfa06d306ddb01aa89",
			"topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x000000000000000000000000d75977fb1c1bf735ddd6c21f7ecfa1405e2cabb8", "0x0000000000000000000000006b4fb976c0a79c2ab5498a1a61e5c25892e74087"],
			"data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAapTXT0MAAA=",
			"blockNumber": 784194,
			"transactionHash": "0x0056a22219c370802fdc5d8bb18d1cc387c97428c6aee95ab794e4e0931e04f5",
			"transactionIndex": 0,
			"blockHash": "0x4bcedd5ee3a6e4f8a4b1e5fddb0707bce7c8cd0f326024a166c1ec577541e855",
			"logIndex": 0,
			"removed": false
		}],
		"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000040000000000000000000008000000000000000000008000000004000000000000000000000000008000000000800000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010040000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000",
		"queryInBlock": 0,
		"result": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
		"transactionHash": "0x0056a22219c370802fdc5d8bb18d1cc387c97428c6aee95ab794e4e0931e04f5"
	}
}
```
  
#### 获取指定钱包和NONCE的交易收据

Params
>String - lbr链地址，0x36aa307a4157653eafa47f327b11963ccf174ed4<br>
>String - 钱包地址
>Number - nonce

Returns
>Object - 交易结果，详细信息如上

Example
```
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"scs_getReceiptByNonce","params":["0x36aa307a4157653eafa47f327b11963ccf174ed4","0xd75977fb1c1bf735ddd6c21f7ecfa1405e2cabb8", 633],"id":101}' https://liberumdex.net/scs

// Result
{
	"jsonrpc": "2.0",
	"id": 101,
	"result": {
		"contractAddress": "0x0000000000000000000000000000000000000000",
		"failed": false,
		"logs": [{
			"address": "0x1652a76c60a73467109527dfa06d306ddb01aa89",
			"topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x000000000000000000000000d75977fb1c1bf735ddd6c21f7ecfa1405e2cabb8", "0x0000000000000000000000006b4fb976c0a79c2ab5498a1a61e5c25892e74087"],
			"data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAESAMdkTVAAA=",
			"blockNumber": 778169,
			"transactionHash": "0x090f923021528d506f17a7c698c6a33839090019ef23629e70fe4e5aa5be8327",
			"transactionIndex": 0,
			"blockHash": "0xd37af071016113c58bed1f0310f200607d9e6125722996a9578225506caba51d",
			"logIndex": 0,
			"removed": false
		}],
		"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000040000000000000000000008000000000000000000008000000004000000000000000000000000008000000000800000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010040000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000",
		"queryInBlock": 0,
		"result": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
		"transactionHash": "0x090f923021528d506f17a7c698c6a33839090019ef23629e70fe4e5aa5be8327"
	}
}
```
#### 获取指定交易哈希的交易信息

Params
>String - lbr链地址，0x36aa307a4157653eafa47f327b11963ccf174ed4<br>
>String - 交易hash

Returns
>Object - 交易结果
blockHash: String - 区块hash<br>
blockNumber: String - 16进制区块号<br>
from: String - 交易发起方<br>
input: String - 交易内容<br>
nonce: Number - 交易nonce<br>
r: String - 交易签名结构体<br>
s: String - 交易签名结构体<br>
shardingFlag: Number - 交易类型，1是执行智能合约，2是转账原始币，3是部署智能合约<br>
to: String - 交易接收方<br>
transactionHash: String - 交易hash<br>
transactionIndex: String - 交易在区块中的索引位置<br>
v: Number - 交易签名结构体<br>
value: Number - 金额<br>

Example
```
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"scs_getTransactionByHash","params":["0x36aa307a4157653eafa47f327b11963ccf174ed4","0xecaacb7a6643ecd58cbc53cf76edf93bf825e0cc549c792a45cf1bb3065b4fe3"],"id":101}' https://liberumdex.net/scs

// Result
{
	"jsonrpc": "2.0",
	"id": 101,
	"result": {
		"blockHash": "0x008a7099f5bd701124079ef1b35c0bae1386aedb64ea7a759df4ed885a2470e7",
		"blockNumber": "0xbf727",
		"from": "0xd75977fb1c1bf735ddd6c21f7ecfa1405e2cabb8",
		"input": "0x1652a76c60a73467109527dfa06d306ddb01aa89a9059cbb0000000000000000000000006b4fb976c0a79c2ab5498a1a61e5c25892e7408700000000000000000000000000000000000000000000000001aa535d3d0c0000e8bdace8b4a644656d6f",
		"nonce": 660,
		"r": 6840248595410363996048256507662366353207120512458591980970692766184514999750,
		"s": 31860061242736890353031238548398400717626347192294322451334788392754560523524,
		"shardingFlag": 1,
		"to": "0x36aa307a4157653eafa47f327b11963ccf174ed4",
		"transactionHash": "0xecaacb7a6643ecd58cbc53cf76edf93bf825e0cc549c792a45cf1bb3065b4fe3",
		"transactionIndex": "0x0",
		"v": 234,
		"value": 0
	}
}
```
#### 获取指定钱包和NONCE的交易信息

Params
>String - lbr链地址，0x36aa307a4157653eafa47f327b11963ccf174ed4<br>
>String - 钱包地址
>Number - nonce

Returns
>Object - 交易结果，详细信息如上

Example
```
// Request
curl -X POST --data '{"jsonrpc":"2.0","method":"scs_getTransactionByNonce","params":["0x36aa307a4157653eafa47f327b11963ccf174ed4","0xd75977fb1c1bf735ddd6c21f7ecfa1405e2cabb8", 634],"id":101}' https://liberumdex.net/scs

// Result
{
	"jsonrpc": "2.0",
	"id": 101,
	"result": {
		"blockHash": "0xdfc0a94e72f4db887f8d56a90db07a05ee62d2e3cb2ec1f429ff20dddc4541e7",
		"blockNumber": "0xbdfbf",
		"from": "0xd75977fb1c1bf735ddd6c21f7ecfa1405e2cabb8",
		"input": "0x1652a76c60a73467109527dfa06d306ddb01aa89a9059cbb0000000000000000000000006b4fb976c0a79c2ab5498a1a61e5c25892e7408700000000000000000000000000000000000000000000000011200c7644d50000e6b58be8af9568686868",
		"nonce": 634,
		"r": 89944765806535187470195512642740513158639821793163186803848716935294213960657,
		"s": 39096147155667292561446716859055444549563580656768500037006920587930562785795,
		"shardingFlag": 1,
		"to": "0x36aa307a4157653eafa47f327b11963ccf174ed4",
		"transactionHash": "0x823b0ea53f1e886f5560057f26def4cdedb8589e906bad7d4bc1403cda89ea42",
		"transactionIndex": "0x1",
		"v": 234,
		"value": 0
	}
}
```

#### 转账数据解析

- 安装[abi-decoder](https://www.npmjs.com/package/abi-decoder#install)
- [添加标准ERC20的ABI](https://www.npmjs.com/package/abi-decoder#add-abis)
- 使用[获取指定哈希的交易收据](#获取指定哈希的交易收据)API获取转账交易的logs
- 调用abi-decoder的[decodeLogs](https://www.npmjs.com/package/abi-decoder#decode-logs-from-tx-receipt)方法解析获取的logs
