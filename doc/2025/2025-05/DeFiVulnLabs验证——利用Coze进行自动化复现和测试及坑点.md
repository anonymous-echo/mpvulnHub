#  DeFiVulnLabs验证——利用Coze进行自动化复现和测试及坑点   
原创 apmozart  Ice ThirdSpace   2025-05-16 01:30  
  
****  
**0x00 Coze空间测试复现**  
  
****  
**最近接触和学习Coze空间https://www.coze.cn/space-preview**  
  
**这是一个类似Manus的AI Agent代理，在某些方面还是不错的，它可以自动编写代码，自动运行获取结果，给了它一个Prompt如下所示：**  
  
****  
**请理解并解析这个漏洞，告诉我它的原理，然后构造测试环境运行，你可以使用Foundry合约测试工具组里的forge工具复现，然后告诉我完整的运行测试结果**  
  
****  
**这是foundry框架的可执行文件： https://github.com/foundry-rs/foundry/releases/download/v1.1.0/foundry_v1.1.0_linux_amd64.tar.gz**  
  
****  
**这是我要执行的测试文件： https://github.com/SunWeb3Sec/DeFiVulnLabs/blob/main/src/test/payable-transfer.sol**  
  
****  
**这是完整的测试框架项目：**  
  
**https://github.com/SunWeb3Sec/DeFiVulnLabs/**  
  
****  
**我已经以附件的格式传给你了（然后上传附件）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5scEI9oDxUeTrUrsLZZ81kUwhAADlu8Je5fUH1D3nvdwN6S3JheCKwQ/640?wx_fmt=png&from=appmsg "")  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o53C7U1hWhibib5kqcp4Dv1DP7u4uOq7T0qegAkibrbBVaZ6S5DibialLBG6g/640?wx_fmt=png&from=appmsg "")  
  
  
  
0x01 直接看结果吧  
## 一、漏洞原理说明  
### 漏洞概述  
  
该漏洞主要是由于在伊斯坦布尔硬分叉中实施EIP 1884后，SLOAD操作的gas成本增加，导致使用Solidity的transfer()  
或send()  
方法向智能合约接收者转移ETH时出现问题。当接收者是智能合约时，这些方法可能无法成功转移ETH。  
### 漏洞产生的具体原因  
#### 1. 硬分叉导致SLOAD操作gas成本增加  
  
在伊斯坦布尔硬分叉中实施EIP 1884后，SLOAD操作的gas成本从200增加到了800。这一变化影响了一些现有的智能合约，特别是那些依赖于transfer()  
或send()  
方法进行ETH转移的合约。  
#### 2. transfer()和send()方法的局限性  
  
transfer()  
和send()  
方法在设计上只提供了2300 gas用于执行接收者合约的代码。当接收者是智能合约时，如果满足以下条件之一，转移操作将会失败：  
- **未实现可支付的回退函数**  
：如果智能合约没有实现可支付的回退函数（payable fallback function），则无法接收ETH。  
  
- **回退函数消耗超过2300 gas**  
：如果智能合约实现了可支付的回退函数，但该函数的执行需要超过2300 gas，那么transfer()  
或send()  
方法将无法提供足够的gas，导致转移失败。  
  
- **通过代理调用导致gas消耗超过2300**  
：即使回退函数本身消耗的gas少于2300，但如果通过代理调用该函数，可能会增加额外的gas消耗，使得总gas消耗超过2300，从而导致转移失败。  
  
### 代码示例分析  
  
以下是测试文件中的代码片段，展示了漏洞的具体表现：  
```
contractSimpleBank{mapping(address=>uint)private balances;functiondeposit()publicpayable{        balances[msg.sender]+= msg.value;}functiongetBalance()publicviewreturns(uint){return balances[msg.sender];}functionwithdraw(uint amount)public{require(balances[msg.sender]>= amount);        balances[msg.sender]-= amount;// 问题出在这里payable(msg.sender).transfer(amount);}}
```  
  
在SimpleBank  
合约的withdraw  
函数中，使用了payable(msg.sender).transfer(amount)  
来转移ETH。如果msg.sender  
是一个智能合约，并且满足上述提到的任何一个条件，那么这个转移操作将会失败。  
### 修复建议  
  
为了避免这个漏洞，建议使用call  
方法，并检查其返回的布尔值，同时结合重入防护机制。以下是修复后的代码示例：  
```
contractFixedSimpleBank{mapping(address=>uint)private balances;functiondeposit()publicpayable{        balances[msg.sender]+= msg.value;}functiongetBalance()publicviewreturns(uint){return balances[msg.sender];}functionwithdraw(uint amount)public{require(balances[msg.sender]>= amount);        balances[msg.sender]-= amount;(bool success,)=payable(msg.sender).call{value: amount}("");require(success," Transfer of ETH Failed");}}
```  
  
在FixedSimpleBank  
合约的withdraw  
函数中，使用了payable(msg.sender).call{value: amount}("")  
来转移ETH，并检查了返回的布尔值success  
。如果转移失败，会抛出错误信息。这样可以确保ETH转移的可靠性。  
## 二、测试环境构造过程  
### 1. 安装Foundry框架  
  
用户提供了foundry框架可执行文件下载链接https://github.com/foundry-rs/foundry/releases/download/v1.1.0/foundry_v1.1.0_linux_amd64.tar.gz ，同时上传了foundry_v1.1.0_linux_amd64.zip文件。将该压缩包解压后，可得到forge  
等可执行文件，将其配置到系统环境变量中，即可完成Foundry框架的安装。  
### 2. 准备测试文件  
  
用户上传了DeFiVulnLabs.zip文件，解压该文件后，得到测试文件DeFiVulnLabs_unzip/DeFiVulnLabs/src/test/payable-transfer.sol  
。该测试文件包含了漏洞合约SimpleBank  
和修复后的合约FixedSimpleBank  
，以及用于测试的合约ContractTest  
。  
### 3. 构造测试环境  
  
使用Foundry合约测试工具组里的forge  
工具来构造测试环境。forge  
工具可以对Solidity合约进行编译、测试等操作。在包含测试文件的目录下，使用forge  
工具可以自动识别并编译测试文件，为后续的漏洞复现测试做好准备。  
## 三、复现漏洞情况  
### 测试思路  
  
在ContractTest  
合约中，定义了两个测试函数：testTransferFail()  
和testCall()  
。testTransferFail()  
用于测试使用transfer()  
方法进行ETH转移时是否会失败，testCall()  
用于测试使用call()  
方法进行ETH转移时是否会成功。  
### 测试结果分析  
#### 1. testTransferFail()  
  
该测试用例首先调用SimpleBank  
合约的deposit()  
函数存入1 ether，然后调用getBalance()  
函数验证余额是否正确。接着，使用vm.expectRevert()  
期望接下来的withdraw()  
函数调用会触发回退。最后调用withdraw()  
函数尝试取出1 ether，由于transfer()  
方法的局限性，当接收者合约的回退函数消耗超过2300 gas时，转移操作会失败，测试用例通过，符合预期。  
#### 2. testCall()  
  
该测试用例首先调用FixedSimpleBank  
合约的deposit()  
函数存入1 ether，然后调用getBalance()  
函数验证余额是否正确。接着调用withdraw()  
函数尝试取出1 ether，由于使用了call()  
方法并检查了返回的布尔值，即使接收者合约的回退函数消耗超过2300 gas，也能正常处理，测试用例通过，说明修复后的合约能够正常工作。  
## 四、完整运行测试结果  
### 编译信息  
```
Compiling 7 files with Solc 0.8.29Solc 0.8.29 finished in 286.94msCompiler run successful!
```  
  
这表明使用Solc 0.8.29编译器成功编译了7个文件，编译过程耗时286.94ms。  
### 测试用例执行情况  
<table><thead><tr><th><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">测试用例</span></span></section></th><th><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">结果</span></span></section></th><th><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">消耗gas</span></span></section></th><th><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">调用追踪</span></span></section></th></tr></thead><tbody><tr><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">testCall()</span></span></section></td><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">PASS</span></span></section></td><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">58853</span></span></section></td><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">[78753] ContractTest::testCall()&lt;br&gt;  - [22537] FixedSimpleBank::deposit{value: 1000000000000000000}()，返回 [Stop]&lt;br&gt;  - [496] FixedSimpleBank::getBalance() [staticcall]，返回 [Return] 1000000000000000000 [1e18]&lt;br&gt;  - [42473] FixedSimpleBank::withdraw(1000000000000000000 [1e18])&lt;br&gt;    - [34260] ContractTest::receive{value: 1000000000000000000}()&lt;br&gt;      - [22537] SimpleBank::deposit{value: 1000000000000000000}()，返回 [Stop]&lt;br&gt;      - 返回 [Stop]&lt;br&gt;    - 返回 [Stop]&lt;br&gt;  - 返回 [Stop]</span></span></section></td></tr><tr><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">testTransferFail()</span></span></section></td><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">PASS</span></span></section></td><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">35375</span></span></section></td><td><section style="margin-top: 8px;margin-bottom: 8px;line-height: 1.5em;"><span leaf=""><span textstyle="" style="font-size: 17px;">[49484] ContractTest::testTransferFail()&lt;br&gt;  - [22537] SimpleBank::deposit{value: 1000000000000000000}()，返回 [Stop]&lt;br&gt;  - [496] SimpleBank::getBalance() [staticcall]，返回 [Return] 1000000000000000000 [1e18]&lt;br&gt;  - [0] VM::expectRevert(custom error 0xf4844814)，返回 [Return]&lt;br&gt;  - [10311] SimpleBank::withdraw(1000000000000000000 [1e18])&lt;br&gt;    - [400] ContractTest::receive{value: 1000000000000000000}()，返回 [OutOfGas] EvmError: OutOfGas&lt;br&gt;    - 返回 [Revert] EvmError: Revert&lt;br&gt;  - 返回 [Stop]</span></span></section></td></tr></tbody></table>### 测试套件结果  
```
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 584.74µs (415.46µs CPU time)Ran 1 test suite in 4.83ms (584.74µs CPU time): 2 tests passed, 0 failed, 0 skipped (2 total tests)
```  
  
这表明整个测试套件执行成功，2个测试用例全部通过，没有失败和跳过的测试用例，测试套件执行耗时584.74µs（CPU时间415.46µs），整个测试过程耗时4.83ms。  
  
  
我看了一下，分析结果并没有太大的问题，  
  
详情可以查看上篇文章DeFiVulnLabs靶场全系列详解（四十二）转账函数固定2300个gas导致合约可用性遭到破坏  
  
  
  
0x02 坑点1  
  
试图让他自动化的下载foundry框架，没想到下载失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSdLfSQjTO5KMUrQdhib6fM843hRhvTEQ2HneOvNibqOjQxpvM1oPyeKiaSNibaIheN1yjLtHG3VVoQ6g/640?wx_fmt=png&from=appmsg "")  
  
****  
****  
**0x03 坑点2**  
  
**于是我上传了附件，让他进行解压安装测试，但是它无法下载7z解压，但是经过多次测试，coze对于文件的下载是存在不确定性的，也就是有时候能下再次成功有时候会下载失败。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5BUYkKfXrz4tXfTQnBK0dAXfUz6zl9ZQUwUichyMfhPGwTvTHPiaTgHicA/640?wx_fmt=png&from=appmsg "")  
  
  
  
0x04 坑点3  
  
规划模式和探索模式各有利弊，探索模式是AI自己思考的，并且思考很可能不充分，执行到一半就说无法执行就退出了。但是某些情况下，探索模式自动化程度更高，这取决于AI脑子是否抽风以及提示词是否够优秀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5hJayvU8fG0cyvkLic6hFjngsyE8Zb5Q5Vp6hU52ETvGr8gSaGAb313w/640?wx_fmt=png&from=appmsg "")  
  
  
  
0x05 坑点4  
  
上面丢给它的存在漏洞的sol地址下载后会出错，重新本地上传了一份给它  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5az93m210SZPcWDkXq2YcseUKAv6tfM3WK8WIcyG5u7SLs8XiaXPzYZw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5DUNLUtaGLwM0S4QGFBUHcJuSup51h5qTOYWJiaomC2BsP08NXgWCFVQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
0x06 坑点5  
  
提示没有forge可执行程序的执行权限，这点倒是小问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5xaBOCa3bicQtlwkYIBaKUNibePl32C4iaPhsFboadXGKmRNpPVjfgLuDQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
0x07 总结  
  
探索模式一次性完成，prompt如下  
  
请理解并解析这个漏洞，告诉我它的原理，然后构造测试环境运行，你可以使用Foundry合约测试工具组里的forge工具复现，然后告诉我完整的运行测试结果  1、你应该先解压zip压缩包 2、然后赋予forge 执行权限 3、使用forge test --contracts   xxxxxx.sol -vvvv 来进行测试 4、深度分析这个漏洞 5、这是这个漏洞的简要概况 Incorrect use of payable.transfer() or send() : Fixed 2300 gas, these shortcomings can make it impossible to successfully transfer ETH to the smart contract recipient. REF  这是foundry框架的可执行文件： https://github.com/foundry-rs/foundry/releases/download/v1.1.0/foundry_v1.1.0_linux_amd64.tar.gz  这是我要执行的存在漏洞的测试文件： https://github.com/SunWeb3Sec/DeFiVulnLabs/blob/main/src/test/payable-transfer.sol  这是完整的测试框架项目： https://github.com/SunWeb3Sec/DeFiVulnLabs/  我已经以附件的格式传给你了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5dzjzALyy7747MGDXT9AQY6L5lGhsrDnhMkz8qK8cn5pCMmlRFwCIibw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o563cdH3vBX4cICSRGFVXxuYiaNibRL47V9Nzwib1T6NMdibpZIfmS2V8aRw/640?wx_fmt=png&from=appmsg "")  
  
  
  
0x08 对比  
  
https://manus.im/share/brWKUSp51ItvVMBpcXNCZ1?replay=1  
  
https://space.coze.cn/web?uri=7502386880629981219%2F%E8%A5%BF%E9%9B%85%E5%9B%BE%E5%87%BA%E5%8F%91%E6%97%A5%E6%9C%AC7%E5%A4%A9%E6%B8%B8-0079db2ba4.jsx&theme=undefined  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSD2H0t9sNNV05LfOicOS7o5PCyiaHmKYOSdtaQQ0sYW4cUQzmMMdCv38vichszNlzYu96klEmE5vFJg/640?wx_fmt=png&from=appmsg "")  
  
  
  
