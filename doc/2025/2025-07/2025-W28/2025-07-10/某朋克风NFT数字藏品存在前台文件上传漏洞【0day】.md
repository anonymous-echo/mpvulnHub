> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4MTkwMTI5Mw==&mid=2247490153&idx=1&sn=f4e566d0f34c146c4e9d3b9d348e2812

#  某朋克风NFT数字藏品存在前台文件上传漏洞【0day】  
原创 Mstir  星悦安全   2025-07-10 05:49  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**朋克风NFT数字藏品系统，对接易支付接口，主要功能介绍  1.艺术品发售：藏品发售购买交易  2.发售日历：限时发售，到期自动上架   3.内容精选：精选藏品出售，限量购买 4.自由市场：用户的藏品可以直接挂售到市场自由交易 5.盲盒：购买盲盒随机抽取藏品，后台可设置盲盒中的奖品**  
  
**Fofa指纹 : 请见文末！**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cEvfdAoIpduQ1Y0Ffe1e5DkxY0vIkqImvBTCX2Q7tRRzNmhm5N5pVllnibYMSHpaWY3H3okDL9Zhg/640?wx_fmt=png&from=appmsg "")  
  
****  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cEvfdAoIpduQ1Y0Ffe1e5Dibc4EUK0ZMch1rSHHZvzUSNdyXEicfMKAJCa9Iib69Wia2icHqiacpJ7aU7w/640?wx_fmt=other&from=appmsg "")  
  
**框架:ThinkPHP 5.0.24 Debug:True**  
## 0x01 漏洞分析&复现  
  
**位于 /application/***/controller/****.php 控制器的 **** 方法通过 **file** 函数上传任意文件，且未加过滤，导致漏洞产生.**  
  
****  

```
public function xxxxx($image)

{

    if (empty($image)) return  Response::fail('请选择要上传的图片');

    $result = xxxxxx::xxxxx($image);

    if ($result['code'] == 1){

        $url = 'http://'.$_SERVER['HTTP_HOST'];

        $url = str_replace('/uploads/', $url.'/uploads/' , $result['path']);

        return Response::success('success',['path'=>$url]);

    }else{

        return Response::fail($result['msg']);

    }

}
```

  
  
**Payload:**  
  
****  

```
POST /xxx/xxxx/xxxxxxx HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 198
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3avSNm8w7tTqLKCf
Host: 192.168.140.128
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36

详细EXP请见文末！

```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cEvfdAoIpduQ1Y0Ffe1e5DnG2POw3rWaAKa2bIBk1YZ466TyrbOvMtYsEQTrjwSyUMNKzsXiam0Lg/640?wx_fmt=png&from=appmsg "")  
  
****## 0x02 知识星球  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
完整POC及源码已放在知识星球中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有250000+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**5，Fofa API 高级会员Key共享**  
  
**6,  高自动化代码审计工具共享**  
  
**圈子目前价格为已降价至129元，现在星球有1000+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于2025.5.12日更新**  
  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhdAXFwVWOKu2WkpehPyeW6H8u2unE5Tg297xNHhicv7y4dE1rXmHGGCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Fofa 高级会员 Key****  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcBUsQ86RewiciagSqyGFsD5GrPCKC6lop95HuichOjFVkgo0VuQvedibEcg/640?wx_fmt=png&from=appmsg "")  
  
超多审计资料，自动化审计工具  
  
![319d33192f5a9f019ec3f7a17cc25bb.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fOtUasHrnibBFTUkOIJJH5Goe8FhSg3arBlw7QLWsJl3xiczb5QnWfRKiaSvcMBPHLuwFjkWuuFicDwQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6g367ZEv3pT7cv8fl3YHMZH47sBH2IMy1J2XYeMNVXDJgLhP1yahI4pw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上千套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通永久VIP，已开通各大源码站VIP**  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**高质量代码审计社区**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eYsOmVcqiczEs2xZkicGt1u6HibInHPVngJzcM5jLf64ncdDFEN0Sfzo5jFkUspBiaCTftaSsheb5JIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
