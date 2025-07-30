#  Nomad Bridge漏洞利用被窃取1.9亿美元   
ang010ela  嘶吼专业版   2022-08-06 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Nomad Bridge漏洞利用事件分析，被窃取1.9亿美元。   
  
Nomad Bridge是一个区块链加密货币跨链平台，支持以太坊、Moonbeam、Avalanche、Evmos和Milkomeda等币种的跨链资产转移。2022年8月1日，Nomad bridge经历漏洞利用，引发价值1.9亿美元资产损失。该漏洞是初始化过程中，“committedRoot”被设置为0引发的。因此，攻击者可以绕过消息验证过程，并从跨链合约中窃取token。  
#  Nomad Bridge简介  
  
Nomad Bridge是一个区块链加密货币跨链协议，允许用户在不同区块链之间实现资产的转移。此外，资产发行者还可以跨链部署token，开发者还可以通过Nomad构建原生跨链应用。Nomad的目标是使用户和开发者能够安全地交互。Nomad支持Avalanche (AVAX)、Ethereum (ETH)、Evmos (EVMOS)、Milkomeda C1和Moonbeam (GLMR)之间的token资产转移。  
# 漏洞利用事件分析  
  
8月1日，Nomad bridge在升级过程中遭遇了漏洞利用。漏洞是初始化过程中，“committedRoot”被设置为0引发的，攻击者可以绕过消息验证过程，滥用copy/paste交易发起攻击。具体来说，用户通过复制原始黑客交易的calldata，并替换为个人的原始地址。然后该交易会被处理，并从Nomad bridge移除资金。在4个小时时间内，黑客、僵尸主机和其他社区成员不断重复该攻击，并成功窃取Nomad bridge几乎所有资金，总计约1.9亿美元。  
# 漏洞利用交易  
  
攻击示例:  
  
以太坊接收100 WBTC转账0xa5fe9  
  
https://etherscan.io/tx/0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySpRJJ8Uw4YmkZHYd7ONT4fSyYnOX81NHxLOYUUUBLbmPLVWvQMwarpA/640?wx_fmt=png "")  
  
多个攻击交易：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySjiatLDf4ZrIsMTGFg1wrCy6JX2dPUO1DVkwP61eJI9iaSf15c8uLSp3Q/640?wx_fmt=png "")  
# 攻击流  
  
以交易0xa5fe9为例：  
  
攻击者调用函数；   
  
在process函数中，会调用acceptableRoot(messages[_messageHash])，这是用来检查root是否提交，以及timeout是否过期的。本例中messages[_messageHash]是0x000。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhyS5tDbVEhlWbRhsiabcom0bjqD2WnhNPmFvq2ecicSlUDhMH788SlWLFRg/640?wx_fmt=png "")  
  
函数acceptableRoot(messages[_messageHash])返回true，消息就被证明了。在初始化时设置为0x0000，因此是true（这也是部署时的错误所在）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhyScBEDibLNmQhUpEoCicyrPg00VUG7eCOtNiaWHO1v3RkmBDFO6AMlylgHw/640?wx_fmt=png "")  
  
消息经过证明后，攻击者就可以向其他链转账。  
# 漏洞  
  
**初始化阶段**  
  
Replica合约在交易0x53fd9中被错误地初始化了，其中“committedRoot”被初始化为0。  
  
**攻击阶段**  
  
因此，攻击者可以直接以任意“_message”调用“process(byte memory _message)”函数，实现验证绕过。  
  
合约地址: 0x88a69  
  
该函数处理确保消息哈希通过检查得到证明。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySf7x9iaQOjdre2YiaBSCrKfLWOw90ga9SrIVRibSGBUTHZCGpOnCffujjQ/640?wx_fmt=png "")  
  
该函数会检查root是否经过证明、处理和确认。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySvSAibMauGMv6VZnygfNzrLAnAvcBxWbqmgUuzNTm49YjJ3owGXgYLVw/640?wx_fmt=png "")  
  
在初始化交易0x53fd9中，所有者发送0，这些root会被设置为1。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySluCdX5icqeaDwC6JvraHYsLIbtBQQBiazcY37970Slu74yfuZcQQmWnQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySpTt9dLRq9AjdiaSiawwoGg0uibnCHkUia0hZMIRJzyGJ6ondCLsC0D7aOw/640?wx_fmt=png "")  
  
因此，0会在0xb9233被检查。  
  
根据prove函数的实现，未经证明的消息的root也是0，因此0会被认为是一个有效的经过确认的root，可以绕过检查。攻击者只需发送交易给Nomad Bridge，就可以获得对应token。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySo93tX6dKDa3c904Wj2PrKBqwgxuiaNkUaVtfC6XicZZNvEJVjagzAicbg/640?wx_fmt=png "")  
# 资产追踪  
  
累计有大约价值1.9亿美元的token从Nomad Bridge被转出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySziaphQhBo1Ioibc7VWb0tMCg0Oaxvv9PKgicOpkCg1P6s9uKbsLicqeyQg/640?wx_fmt=png "")  
  
参考及来源：https://www.certik.com/resources/blog/28fMavD63CpZJOKOjb9DX3-nomad-bridge-exploit-incident-analysis  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySaUiaPicLos1wu0pVF34CgsJe6CJ4ZRnWUkXCJkdDa0wn3leY4mQqD8cQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28P5BhVkNNtoXq2P77nHhySwwBpQ4ZJgUBf7f7ibuGT0B3QbCe0fCfeEte6gUdrVxr4o52XTAEHCoA/640?wx_fmt=png "")  
  
