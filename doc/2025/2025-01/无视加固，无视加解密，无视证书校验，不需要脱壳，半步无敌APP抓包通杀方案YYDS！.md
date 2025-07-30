#  无视加固，无视加解密，无视证书校验，不需要脱壳，半步无敌APP抓包通杀方案YYDS！   
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-01-08 10:03  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
    经常跟APP打交道的铁汁可能都知道，APP作为一个新兴的web载体，上面的对抗手段比传统的web只多不少。各家厂商的企业加固把前线的兄弟们搞得是苦不堪言，单向证书，双向证书更是越来越变态。  
  
    古代打仗的时候有一句话，兵马未动粮草先行。同样的抓包就是测试的先行官。数据包都抓不到，还谈什么测试呢？想要顺顺利利的测试的前提是能够舒舒服服的抓到包。  
  
  
    今天斯叔给大家介绍一个半步无敌抓包通杀方案，无视加固（加不加固都不影响这个方案的执行![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_5@2x.png "")  
），无视加解密（绕过了加解密的逻辑，不需要关注加解密的过程了![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_45@2x.png "")  
），无视证书校验（同样绕过了证书校验的逻辑，也不需要关注证书校验的过程了![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_7@2x.png "")  
），不需要脱壳（我脱壳主要是干嘛？研究加解密？加解密都无视了我还脱壳干嘛？![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
）。全是干货，且听我娓娓道来。  
  
