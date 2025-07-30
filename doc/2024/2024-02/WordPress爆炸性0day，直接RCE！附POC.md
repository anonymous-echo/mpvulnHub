#  WordPress爆炸性0day，直接RCE！附POC   
网络安全007  信安404   2024-02-23 17:50  
  
      
## 免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
师傅们，过年好呀！  
现在安全行业越来越难混了，安全的门槛越来越低了，现在如果想转安全行业还需要去报班的话，趁早别想了，自从AI的崛起，对于安全圈子很多内容已经完全可以使用AI进行了，根本无需再从课程上去一步步精讲，现在更多的是注重代码审计，内网，手工挖掘思路，如果有想往这些方面走的可以慢慢沉淀；如果还是想转安全单纯做个安服，那么还是别转安全了，去别的行业说不定出路更多，因为2023年底到现在很多安全厂商已经开始裁员，俗称优化，懂得都懂......![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Social.png "")  
  
  
    最近WordPress出现爆炸性0day，可以直接RCE，不知师傅们有没有关注呢。  
  
**老样子，师傅们如果有用到该平台的漏洞，要记得及时找厂商进行修复以及做好防护策略，这样子就可以预防一下啦。**  
  
**一、资产搜集**  
```
fofa:body="/wp-content/themes/bricks/"
```  
  
  
**二、复现过程**  
  
1.首先访问存在WordPress Bricks Builder 插件的网站，然后右键查看网页源代码或者使用抓包工具抓取返回的数据包，直接搜索参数  
**nonce**，获取其参数值。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoAxdIflyljUOjQl6QHo75MfiasDiawwMe3qNbfoddsQZP2oFVT3hS3DUs3T9IicX1Mia4MSwQ6YuziafQ/640?wx_fmt=png&from=appmsg "")  
  
2.漏洞路径为：/wp-json/bricks/v1/render_element，然后使用构造好的POC进行nonce的替换，直接进行命令执行，**获取服务器敏感信息以及进行敏感操作**。其中执行的命令可以根据自己的需要进行更改即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoAxdIflyljUOjQl6QHo75MPxHiaoGWJ0ic6zc5WCwZ6W3vxE5xgSHich1VxUxicOCib3rFoWfjUsdQ38A/640?wx_fmt=png&from=appmsg "")  
  
  
  
Tips  
  
## 下载POC：公众号后台回复“240223”  
  
后台回复“  
**交流群**”获取技术交流群链接，或扫码加入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bQCwTicVAUKUD6QThIzhZRxHZqsISxTR4Riaa3icWGHMLiclHIE62xEeicibeELS3McDKT1O2jy2ia6wvOeLvyInOiblfQ/640?wx_fmt=png "")  
  
  
  
  
  
往期推荐  
  
  
[afrog 漏洞检测工具的官方 PoCs库（2月19日更新）](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487609&idx=1&sn=071ef57168643e424f22e70c2d5981ba&chksm=c3040ac0f47383d6c20343484b33905df2adb90403e4b7d28259f22480548a3802a9c12d2f96&scene=21#wechat_redirect)  
  
  
[多人运动又添神器，快来一起！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487603&idx=1&sn=8bd325ec854514b3ad615f748af5038f&chksm=c3040acaf47383dcc7e6e7d75536548bd4afadd5356a879100bd32342fa930061bc336e7671e&scene=21#wechat_redirect)  
  
  
[一款自动化提权工具](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487603&idx=2&sn=4cc78cf9e491668475fee3b857bf6723&chksm=c3040acaf47383dc11ba138c947f04d9cdf8bd67d200bd31e6ceb002cee2d0ad8fe717c87ad1&scene=21#wechat_redirect)  
  
  
[浅谈微信小程序测试技巧](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487586&idx=1&sn=f6216b976bef93e2ea7d2bd93ef9526f&chksm=c3040adbf47383cde79bda12404b42c30ac4c90a53d353ce5c071f3b1e6d1ec8e00d088b06f9&scene=21#wechat_redirect)  
  
  
[【工具更新】Nessus 24年2月18日更新_windows 版Cracked（附下载）](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487586&idx=2&sn=b8f85aa5bd468d5f1d711a619f76a417&chksm=c3040adbf47383cd1e03d676fac06115939b0799d26269e367fb1c6438e747fa72d6031bb9e6&scene=21#wechat_redirect)  
  
  
[APP渗透测试环境搭建](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487368&idx=1&sn=8834b7286c3f35abb5404b014551a3ad&chksm=c3041531f4739c276d40fc0abb82e3823e51be2d1aea400a637df685122c9bdb58c07cde8ae2&scene=21#wechat_redirect)  
  
  
[漏洞扫描的工具 -- Golden-hooped Rod（2月15日更新）](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487365&idx=1&sn=018042e091abade77478283b8c731b95&chksm=c304153cf4739c2a9d0485ca26d986bcc5fd2fceb0e6cf5d6c6654b57eb06fed9bd3641efe93&scene=21#wechat_redirect)  
  
  
[接近真实世界的web漏洞靶场](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487355&idx=1&sn=984725ab5da3b33fe97d02931f7ece03&chksm=c30415c2f4739cd4ea01ff36bef0ae673647af489a38676bf56c12b001e201b7d4cd2723575f&scene=21#wechat_redirect)  
  
  
[微信0day漏洞？恶意代码成功执行！附恶意代码构造](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487355&idx=2&sn=278e7a8d4a3acc7a3632d2b85741d2d1&chksm=c30415c2f4739cd4f3a6058fb19731cca268e4b732b29d7cbfbc073942ae2a3d33a9e13c902c&scene=21#wechat_redirect)  
  
  
[【绝对好用】黑客使用什么截图软件？](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487335&idx=1&sn=e0e27b89615299d3badee733c9e74a9d&chksm=c30415def4739cc86568b3e821536e4b3f8fa0ee401a6101605d7fc407a5f535adb1124c4efb&scene=21#wechat_redirect)  
  
  
[假期如何优雅的远程办公/运维/测试？](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487252&idx=1&sn=48f3c4234f5921396abf83b5d4f88e4c&chksm=c30415adf4739cbbb0e1a62d8fa113b2d2ab763fc29d99634cdca07016acaa8ca6df5fbb94db&scene=21#wechat_redirect)  
  
  
[莫伸手，伸手必被抓，史上最强应急响应工具|应急溯源](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487252&idx=2&sn=eb4a7bb9a158dece580d20d595a52877&chksm=c30415adf4739cbb1d821b619b141cf5dc609eec5a27d91539c2e100a0ab4993fe6e9e94f977&scene=21#wechat_redirect)  
  
  
[人手一个的渗透神器被大佬下手了，直接二开Plus版本！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487202&idx=1&sn=530f2eba36a8681c44c5263dc83270de&chksm=c304145bf4739d4d3000f9a36a9adec7a20853a9a78032e8b60c52f40635d0f9b887b998ef3a&scene=21#wechat_redirect)  
  
  
[【八年磨一剑】内部工具被流出后，大佬霸气公开](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487181&idx=1&sn=27ac1201e97997a32a678aa3111b8a65&chksm=c3041474f4739d626430876483cfeab53efc3b5bd6c92f2ca9f98376de11f0b93872477d819b&scene=21#wechat_redirect)  
  
  
[某大佬高危漏洞利用工具外泄，速存！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487128&idx=1&sn=97e9df98d22a6b501c237d71e6dfdc52&chksm=c3041421f4739d37b1b72ece9bae463ad0213940aa102d6214d12b40e054ce381b7e9e6e146d&scene=21#wechat_redirect)  
  
  
这个渗透利器都2024版了，你不会还没更新吧？  
  
