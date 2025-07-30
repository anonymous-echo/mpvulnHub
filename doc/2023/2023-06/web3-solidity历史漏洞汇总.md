#  web3-solidity历史漏洞汇总   
原创 neicun  ChaMd5安全团队   2023-06-13 09:01  
  
Solidity是以太坊生态系统中使用最广泛的智能合约编程语言之一。然而，像任何软件一样，Solidity编译器也存在一些缺陷和漏洞，这些问题可能会导致智能合约的不安全或不可靠性。本文将介绍一些solidity编译器历史上的一些高危漏洞  
  
## solidity特点  
  
solidity是以太坊智能合约生态系统中最常用的编程语言之一。它允许开发人员编写可执行的智能合约，并将这些合约部署到以太坊区块链上。 Solidity编译器通过将高级Solidity源代码转换为机器可读的EVM字节码来实现这一过程。  
  
solidity是一种静态类型的编程语言，用于开发在EVM上执行的智能合约。目前，使用EVM的区块链平台可以使用soldiity来开发智能合约，如以太坊、以太坊经典、币安链、雪崩链、波场链等。  
  
solidity有很多优点，第一是solidity在编译时会执行静态类型检查，从而帮助开发人员避免一些常见的编程错误。第二，Solidity编译器使用内存管理系统来分配和释放内存，帮助开发人员避免一些内存管理错误。第三，Solidity编译器提供了一套异常处理机制，帮助开发人员处理运行时错误。  
## 历史高危漏洞  
### 有条件终止前的存储写入删除  
  
在编译器版本0.8.13中，如果调用的函数中含有内联汇编return()或stop()和条件判断的函数可能会导致不正确的优化。  
#### 复现  
```
contract C {
	uint public x;
	function f(bool a) public {
		x = 1; // This write is removed due to the bug.
		g(a);
		x = 2;
	}
	function g(bool a) internal {
		// The relevant part of this function is that it can
		// both return to the caller and terminate the transaction.
		// The bug will show its effects in the cases in which
		// the transaction is terminated (i.e. if a is false).
		// In this case the write x = 1 above will be missing.
		if (a) return;
		assembly { return(0,0) }
	}
}

```  
  
首先使用solc-select选择0.8.13版本的编译器：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PaHFqdQlrZfQ6COOZkGdp98l3Ab69BVice5JGsg3XHqY8CAfLb08L1FA/640?wx_fmt=png "")  
  
编译合约，并开启via-ir和optimize：  
```
solc --bin --abi --via-ir --optimize c.sol

```  
  
得到字节码和abi：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PWFkddG3savgoP4wWzkx98Hib2FlLKlI3SwPrEhKhH3F2kB3QwddWoWA/640?wx_fmt=png "")  
  
image-20230506091949073  
  
将字节码保存到bytecode.txt文件中，web3.py脚本将字节码部署到本地测试网：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1Pljz3usHpqb5hP3emSh7PIS81RicUiaicADicjxqvqUwHyFvSnPMg3281gw/640?wx_fmt=png "")  
  
image-20230506092215588  
  
部署成功：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PK1bRib8V85WaA3A5hznbZHkS5S53bIxDT5ia6vXj6kkaBvn2ciae8QYQA/640?wx_fmt=png "")  
  
在remix中查看，首先x的初始值为0:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PK1bRib8V85WaA3A5hznbZHkS5S53bIxDT5ia6vXj6kkaBvn2ciae8QYQA/640?wx_fmt=png "")  
  
调用f并设a为false后，x为0：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PAotpmAicvvjFI9IBe5xzlds49PdusOhu9TT0Lgz4yaBheqjoQvIBOUQ/640?wx_fmt=png "")  
  
再次调用f，这时设置a为true，这时候x为2:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PM5G8qVFMhKuwEIhkf3L07PVicR196Rx1IibL2qrQOG8UPhVsSmeMHn7w/640?wx_fmt=png "")  
  
这说明在运行return(0,0)的时候x=1被忽略了。  
#### 触发条件  
  
首先内联汇编汇编中有return(0,0) 或者 stop()语句。其次是这个函数不应该有任何的变量读写即该函数是pure类型的。最后，函数中应该有个if控制流，其中一个是return(0,0) 或者 stop()语句，另一个是Storage的额外写操作。  
  
在打开Yul优化选项之后，优化器会执行Unused Store Eliminator，优化掉多余的写操作：  
```
{
    x = 1; // 多余语句，被优化
    x = 2;
}

{
    x = 1; // 由于函数最后会revert，所以也是多余语句，被优化
    revert();
}

```  
  
但优化器此时将return(0,0) 和 stop()当作必然会revert处理了，当这两个语句在if的一个分支中，而另一个分支正常时，优化器就会错误地将前面的写操作优化。  
### 关于内联汇编的内存副作用的优化器错误  
  
在编译器版本0.8.13中有一个新的Yul优化步骤，用于删除未使用的内存和存储使用。  
  
Yul优化器将最外层的Yul块中从未读取的所有内存写入视为未使用，并将其删除。当一个Yul块是整个Yul程序的时候，这么做是对的。但如果一个程序分为多个块时，优化器会单独优化每个块。这样做的后果是如果一段内联汇编汇编程序被分成多个部分，后面的代码块在访问前面代码块中存储在内存中的变量时会发生错误。  
#### 复现  
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract C {
    function f() external pure returns (uint256 x) {
        assembly {
            mstore(0, 0x42)
        }
        assembly {
            x := mload(0)
        }
    }
}

```  
  
使用0.8.13版本的solc编译该合约，使用命令为：  
```
solc --bin --abi --optimize 2022-4.sol

```  
  
生成相应的abi和字节码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PMqOI5gCpBibxiax5ibw17Xo32B6rD7neoEzI63qeACTBZHOwDRia8KI8tw/640?wx_fmt=png "")  
  
image-20230522175029587  
  
使用web3.py脚本部署该合约：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1Pg3ylvVPgQGXhqdKY92RvDYMQiarvu9FjrtgUq9oXIfUJrzXsq0MKEbg/640?wx_fmt=png "")  
  
image-20230522180202866  
  
在remix中调用合约的f函数，可以发现返回结果为0，说明第一个内联汇编块中的mload语句被优化：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PDTehmoLicC9LqjbaaWibEogjbN5gKhv83Uk6JszibtNlicSicsOnlic4xYqw/640?wx_fmt=png "")  
### 优化器Keccak缓存错误  
  
在调用Keccak256内置函数的时候，如果被哈希计算的内容已知，字节码优化器会进行特殊优化。但这里又个错误，如果被哈希的内容相同，但长度不同，这时优化器会错误地认为这两个哈希值相同。  
```
contract C {
  function bug() public returns (uint a, uint b) {
    assembly {
      mstore(0, 0)
      // The optimizer computes the value at compile time:
      // 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
      a := keccak256(0, 32)
      // The optimizer incorrectly uses the cached value
      // and transforms the next line to
      // b := 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
      // instead of 
      // b := 0xe2b9f9f9430b05bfa9a3abd3bac9a181434d23a707ef1cde8bd25d30203538d8
      b := keccak256(0, 23)
    }
  }
}

```  
  
由于被哈希的内容已知，所以哈希计算会在编译时完成。同时，两次被哈希的内容相同，这时两个哈希值a和b被优化器认为是相同的，尽管被哈希值实际长度不同。  
```
contract C {
  function bug() public view returns (bool ret) {
    assembly {
      let x := calldataload(0)
      mstore(0, x)
      mstore(0x20, x)
      let a := keccak256(0, 4)
      // even though the memory location is different,
      // the 32-byte content is the same.
      let b := keccak256(0x20, 8)
      // Here `a` and `b` were considered equal,
      // leading to `ret` being incorrectly set to true.
      ret := eq(a, b)
    }
  }
}

```  
  
在下面这个例子中，使用mstore将相同的值存放在下一个32bytes的内存中，但优化器依然认为它们是相等的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PheGSP3a325SibExuCUeFI0NVribH1DxbotN9jMiaAQKwRa0Kib1Hqs1mkw/640?wx_fmt=png "")  
  
image-20230523164234024  
  
究其原因，是在进行loadFromMemory操作时，是以32bytes为粒度进行，从而忽略了小于32bytes的情况。  
#### 复现  
  
由于这个bug是0.8.13之前的所有版本都存在，所以这里使用0.8.0版本，开启优化器编译合约：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PiaH5BfsLibjF4JHrp4aI6CFLSAR63ubvf27TQAYTiaCgelyMCFaicqWd0g/640?wx_fmt=png "")  
  
image-20230523165230894  
  
使用web3.py部署合约：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PBmqTpxeRH6xDB2Spb6tF0r23vNVT1eAqXEfoqmOxVxwibfibpia5dYWSA/640?wx_fmt=png "")  
  
使用remix调用bug函数，返回结果为true：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PVr0cBSPQswgNWShej2VeOzxlcrnAvoQDeo2At7Ar5FLWjFTfjVkqyQ/640?wx_fmt=png "")  
### 空Byte Array复制错误  
  
在solc版本小于0.7.4的编译器中，如果创建了bytes或string类型的列表，复制空的bytes或string类型进入这个列表，再对这个列表的length或使用push()进行操作，会让这个列表中的首个元素变成非0值。  
```
contract C {
    bytes data;
    function f() public returns (bytes memory) {
        // Empty byte array
        bytes memory t;
        // Store something else in memory after it
        uint[2] memory x;
        x[0] = type(uint).max;
        // Copy the empty byte array to storage,
        // this will copy too much from memory.
        data = t;
        // Create a new byte array element,
        // this will only update the length value.
        data.push();
        // Now, `data[0]` is `0xff` instead of `0`.
        return data;
    }
}

```  
#### 复现  
  
将测试代码导入remix，选用编译器版本0.7.0:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PDSdDic6V27GmMVVmd53zkF2VicVBZvAiaojEmrLMpMBFJcQhicbEXwMjUw/640?wx_fmt=png "")  
  
部署合约并调用f函数，可以看见返回的结果为非0值0xff：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBRcnTYQ23nzL4JQ5Det7j1PZvKuoMYSJE1Ff7yibU2XHlNRJsiaON1GX5RibY8ia79VsAGuLXpzbPmfvQ/640?wx_fmt=png "")  
  
  
招新小广告  
  
ChaMd5 Venom 招收大佬入圈  
  
新成立组IOT+工控+样本分析   
长期招新  
  
欢迎联系  
admin@chamd5.org  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBR8nk7RR7HefBINILy4PClwoEMzGCJovye9KIsEjCKwxlqcSFsGJSv3OtYIjmKpXzVyfzlqSicWwxQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
