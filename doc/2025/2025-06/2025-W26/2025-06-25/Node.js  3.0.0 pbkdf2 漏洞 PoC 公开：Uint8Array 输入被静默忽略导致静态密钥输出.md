> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531289&idx=1&sn=5722bb18f3e15632dd080ec4df5c6ca7

#  Node.js < 3.0.0 pbkdf2 漏洞 PoC 公开：Uint8Array 输入被静默忽略导致静态密钥输出  
 Ots安全   2025-06-24 10:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
概括  
  
在历史版本但声明受支持的 Node.js 版本（0.12-2.x）上，pbkdf2 会默默忽略 Uint8Array 输入  
  
这仅影响 Node.js <3.0.0，但pbkdf2声称：  
- 支持 Node.js >= 0.12（并且该 repo 似乎正在持续努力维护这一点）  
  
- 支持Uint8Array输入（输入针对 Uint8Array 进行类型检查，错误消息包括例如“密码必须是字符串、缓冲区、类型数组或 DataView”  
  
细节  
  
错误在于toBuffer方法  
  
这个漏洞甚至以某种方式进入了测试：eb9f97a  
  
在那里，resultsOld（不匹配的地方results）只是从空密码/盐生成的无效输出，而不是提供的  
  
概念验证  
  
在 Node.js/io.js < 3.0.0 上  
  

```
> require('pbkdf2').pbkdf2Sync(newUint8Array([1,2,3]), newUint8Array([1,3,4]), 1024, 32, 'sha256')
<Buffer 2153 cd 5b a5 f0 15392f 68 e2 408b 21 ba ca 0e dc 7b 20 d5 45 a4 8a ea b5 959f f0 be bf 66>

// But that's just a hash of empty data with empty password:
> require('pbkdf2').pbkdf2Sync('', '', 1024, 32, 'sha256')
<Buffer 2153 cd 5b a5 f0 15392f 68 e2 408b 21 ba ca 0e dc 7b 20 d5 45 a4 8a ea b5 959f f0 be bf 66>

// Node.js crypto is fine even on that version:
> require('crypto').pbkdf2Sync(newUint8Array([1,2,3]), newUint8Array([1,3,4]), 1024, 32, 'sha256')
<Buffer 7810 cc 84 b7 bb 85 cd c8 37 ca 68 da a9 4c 33 db ae c2 3d 5b d4 9576 da 33 f9 95 ac 51 f4 45>

// Empty hash from Node.js, for comparison
> require('crypto').pbkdf2Sync('', '', 1024, 32, 'sha256')
<Buffer 2153 cd 5b a5 f0 15392f 68 e2 408b 21 ba ca 0e dc 7b 20 d5 45 a4 8a ea b5 959f f0 be bf 66>
```

  
  
影响  
  
输出静态哈希并将其用作密钥/密码可能会完全破坏安全性。  
  
也就是说，现在没有人应该在任何地方使用这些 Node.js 版本，所以我建议删除它们。  
  
但是，这个库不应该在输出静态数据的同时假装在这些版本上工作。  
  
仅更新到固定版本是不够的：如果有人在 Node.js/io.js < 3.0.0 中使用pbkdf2lib （不要与 Node.js 混淆crypto.pbkdf2）或任何依赖于它的版本，请重新检查这些密钥的位置/它们的使用方式，并采取相应的措施  
  
所有内容均可点击下方的阅读原文链接进行跳转  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
