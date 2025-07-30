#  寻找 TeamViewer 0day 漏洞（二）：逆向身份验证协议   
原创 一个不正经的黑客  一个不正经的黑客   2024-10-06 18:55  
  
如果没有看过第一部分的读者，可以先从第一部分看起：[寻找TeamViewer 0day漏洞—第一部分：故事的开始](http://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505976&idx=1&sn=f89635b0fdc90f31c1b644dee84014bb&chksm=c0ce2341f7b9aa57cc4648b9e23d8dca27cf0aea3cfbe2166173c85f7c63104e253ea84abea8&scene=21#wechat_redirect)  
  
### 本文开始  
  
我开始逆向TeamViewer客户端，以了解认证过程是如何进行的。  
  
不过，我将跳过这部分内容，因为最终我是通过逆向服务端来弄清楚认证方法的。  
  
逆向客户端的过程非常繁琐，因为存在重叠I/O、多线程处理、控制流保护(CFG)等复杂情况，这让我多次陷入无用的路径和迷宫般的分析过程。  
  
我认为展示客户端的逆向过程不会对这篇文章有实质性的贡献，所以我将直接跳过，进入重要的部分。  
  
**过程总结**：  
1. 客户端在**第一部分**中提到的认证消息中发送一个挑战(challenge)。  
  
1. 服务器响应时包含服务器的挑战以及根据客户端挑战计算出的回应。  
  
1. 客户端应验证该挑战，以确保不会连接到恶意的TeamViewer服务。在我们的场景中，这部分可以忽略，我们只需要正确认证到服务。  
  
1. 客户端基于服务器的挑战计算出响应，并在接下来的消息中发送。  
  
**从哪里开始？**  
  
在开始逆向客户端时，我发现了一个很有价值的线索。我们知道TeamViewer记录了以下日志：  
```
2024/05/26 19:03:04.770 3268 3660 S0!! InterProcessNetwork::Received_IPCAuth() invalid response
```  
  
因此，我首先在IDA中简单地搜索了这个字符串，结果返回了以下交叉引用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZpIGeGaC0vPzQO56caKf65yOaBjzMD6B5euNz6aNKKDe7NyWV3utsKg/640?wx_fmt=png&from=appmsg "")  
  
通过回溯代码，我们可以找到最终进行比较的地方，也就是在检查客户端发送的响应是否与正确的值匹配。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZ0cl5QzeIbG8QVxDDiaiaFSJDlVp6stZHm7exPT3td5wluPRib3j1Euv0Q/640?wx_fmt=png&from=appmsg "")  
  
在研究这个过程时，发现下列函数负责返回预期的输出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZ60GfZ19BhE3fmAViaGibaU4kxfSggG7wz7t8BR4uJicnYIzHR1MzUXyEQ/640?wx_fmt=png&from=appmsg "")  
  
我将展示该函数所遵循的过程。  
  
这个函数其实是一个辅助函数，它实际上调用了另一个函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZg9MOx7uXw3Yp9ZJrn6SLbdZskQ7eXqDCwpqvy7ibP4TPs8dPQ0Brtng/640?wx_fmt=png&from=appmsg "")  
  
最终，我们（在再次调用了一个辅助函数之后）进入了执行所有关键操作的核心函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZYpA03cz4tgvVeIELtKCfZG5mEz9qE1WW1u6J0FhagrUOhVrQLJn9PA/640?wx_fmt=png&from=appmsg "")  
  
接着，我们进入一个循环，在循环体内不断调用一个函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZDicVXj2Boib8ibZicoW1llVZQfjSqamOzHiavoibXz08XJWGktjmbKNS4fxA/640?wx_fmt=png&from=appmsg "")  
  
这个函数的作用是什么？  
  
我将展示反编译代码的前几行：  
```
_int64 __fastcall sub_7FF7E93DD240(_DWORD *a1, _DWORD *a2)
{
  [...VARS...]

  v2 = a1[1];
  v3 = a2;
  v4 = a1[2];
  v5 = a1[3];
  v6 = a2[5];
  v83 = *a2;
  v85 = a2[1];
  v7 = v2 + __ROL4__(*a2 + (v5 ^ v2 & (v4 ^ v5)) + *a1 - 680876936, 7);
  v80 = a2[2];
  v8 = v7 + __ROL4__(v85 + (v4 ^ v7 & (v2 ^ v4)) + v5 - 389564586, 12);
  v84 = v3[3];
  v9 = v8 + __ROL4__(v80 + (v2 ^ v8 & (v7 ^ v2)) + v4 + 606105819, 17);
  v78 = v3[4];
  v10 = v9 + __ROL4__(v84 + (v7 ^ v9 & (v7 ^ v8)) + v2 - 1044525330, 22);
  v77 = v3[6];
  v11 = v10 + __ROL4__(v78 + (v8 ^ v10 & (v9 ^ v8)) + v7 - 176418897, 7);
  v12 = v11 + __ROL4__(v6 + (v9 ^ v11 & (v10 ^ v9)) + v8 + 1200080426, 12);
  v13 = v12 + __ROL4__(v77 + (v10 ^ v12 & (v11 ^ v10)) + v9 - 1473231341, 17);
```  
  
你认出它了吗？如果认出来了，恭喜你。如果没有，也不要担心，我也是一开始没认出来，直到借助 ChatGPT 才发现。  
  
这是 **MD5 核心函数**。也就是说，TeamViewer 正在执行 MD5 哈希运算。现在，让我们来看看具体在哈希什么内容。  
  
在这个漏洞利用执行过程中，我们收到的挑战是：  
  
03f22fac bc141ee3428422e955cc e3 e3  
  
但在分析传递给 MD5 哈希核心函数的参数时，我们看到如下内容：  
  
TV 将挑战值与以下字节进行拼接：  
  
40C289053BE8 C1697D74D836FC1D2F6E  
  
我尚未测试过，但我认为可以通过我们在第 1 部分中提到的 IPCPassword 注册表项来更改它。  
  
一个重要的细节是，这是 **服务器** 挑战所使用的密码。  
  
对于 **客户端** 挑战，使用了不同的密码：  
  
436E6762F25EA8 D704E522BF A55DA16A  
  
因此，基本上为了进行认证，我们只需要计算 MD5(CHALLENGE+STATIC KEY)。  
  
完成此步骤后，我们需要发送 ControlIPC，并提供正确的进程 ID (PID)。我相信任何当前进程的 PID 都可能有效，但我尚未测试过。  
  
在漏洞利用中，发送的是当前进程的 PID。  
  
指定一个不存在的进程 PID 会导致失败。  
  
在 **第三部分** 中，我们将编写漏洞利用程序，并最终使用它来进行特权提升。  
  
系列即将完结，请保持关注公众号，第一时间获取更新。  
### Thanks  
  
thanks for https://pgj11.com/posts/Finding-TeamViewer-0days-Part-2/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Gjzq8xnQKEV0l6dDbjlSQv0HZ8EvGaTPQxhVdg1v07h5gy6vSlnjEBAQTgZPvjyzH9yAlRlkraemufMwgr2A6w/640?from=appmsg&wx_fmt=gif "")  
  
往期推荐  
  
  
  
[寻找TeamViewer 0day漏洞—第一部分：故事的开始](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505976&idx=1&sn=f89635b0fdc90f31c1b644dee84014bb&chksm=c0ce2341f7b9aa57cc4648b9e23d8dca27cf0aea3cfbe2166173c85f7c63104e253ea84abea8&scene=21#wechat_redirect)  
  
  
[至暗时刻！Linux 史诗级核弹0day EXP公开](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505954&idx=1&sn=afb463f7f9cb6593e20a1f8aa6902fc1&chksm=c0ce235bf7b9aa4debd63e160ff78c2f165e3d8f701a63ca5c45e2c84f12097eb75a51aebb08&scene=21#wechat_redirect)  
  
  
[Android活动（Activities）Exploiting 技术](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505943&idx=1&sn=7c0f15870782a61558fbb2add2e482cd&chksm=c0ce236ef7b9aa78fd2c14358e7051d3d63753b15c7406030b871971d64af28545e44e5b6c63&scene=21#wechat_redirect)  
  
  
[打破 BurpSuite Chromium 的限制重写JS文件](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505910&idx=1&sn=9c06e8e5e9b8ffcf6f83c1c1c3bdba7b&chksm=c0ce2c8ff7b9a599072651a23001282343f9861bf32ed9fcdf197af6f7283b4b15bf13f3e741&scene=21#wechat_redirect)  
  
  
[寻找IDOR漏洞：Key Endpoints and Resources](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247505935&idx=1&sn=69ea4216b3d472df4bc011e01a477e21&chksm=c0ce2376f7b9aa606100604b65ad87b35aea2d08ee6e0081774c79160ecd65bb4c557e1fe137&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/cxf9lzscpMqjqAx55PbibVKTjsGDX1GuZcriayUYDsV3Zib636CcYC8vMpibp2uMgCcPicdc0hJAajP4iaRhn0mA8V0g/640?wx_fmt=gif&from=appmsg "")  
   
  
  
