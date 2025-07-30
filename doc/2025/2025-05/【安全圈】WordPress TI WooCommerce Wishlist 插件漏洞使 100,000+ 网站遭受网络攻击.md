#  【安全圈】WordPress TI WooCommerce Wishlist 插件漏洞使 100,000+ 网站遭受网络攻击   
 安全圈   2025-05-29 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhzJGtyNr0uF4pKS49m8wVFCA6BXVAicTFAgOnp8Afr4qUNbtwhTJHHicJEtib5NwTNQRemmcCOm2nfw/640?wx_fmt=png&from=appmsg "")  
  
流行的 TI WooCommerce Wishlist 插件中的一个严重安全漏洞已使超过 100,000 个 WordPress 网站面临潜在的网络攻击，安全研究人员警告即将面临利用风险。  
  
该漏洞被指定为 CVE-2025-47577，并被分配了最高 CVSS 分数 10.0，它使未经身份验证的攻击者能够将任意文件上传到受影响的网站，从而可能导致服务器完全受损。  
  
TI WooCommerce Wishlist 插件为 WooCommerce 商店添加了愿望清单功能，已成为全球电子商务网站的重大安全责任。  
  
该漏洞特别影响版本 2.9.2 和所有以前的版本，插件开发人员目前没有提供补丁版本。  
  
鉴于其广泛部署和潜在攻击的严重性，该安全漏洞是最近几个月发现的最严重的 WordPress 插件漏洞之一。  
  
Patchstack 分析师在例行安全评估中发现了这个关键漏洞，并立即尝试在 2025 年 3 月 26 日联系插件供应商。  
  
然而，在近两个月没有收到开发人员的回应后，该安全公司于 2025 年 5 月 16 日将漏洞详细信息发布到他们的数据库中，随后于 2025 年 5 月 27 日发布了公开公告。  
  
缺乏供应商响应使网站管理员除了从他们的安装中完全删除插件之外，别无选择。  
## 技术感染机制  
  
该漏洞源于插件的文件上传处理机制中的一个根本缺陷，特别是在函数中。tinvwl_upload_file_wc_fields_factory  
  
此功能通过 WordPress 的原生功能处理文件上传，但故意禁用通常会防止恶意文件上传的关键安全验证。wp_handle_upload有问题的代码展示了绕过 WordPress 内置安全措施的危险配置：  
```
function tinvwl_upload_file_wc_fields_factory( $file ) {
    if (!function_exists( 'wp_handle_upload' ) ) {
        require_once( ABSPATH . 'wp-admin/includes/file.php' );
    }
    $upload = wp_handle_upload(
        $file,
        [
            'test_form' => false,
            'test_type' => false,
        ]
    );
    return $upload;
}
```  
  
严重安全故障通过 parameter 发生，该参数显式禁用通常会将上传限制为安全文件类型的文件类型验证。'test_type' => false  
  
此配置允许攻击者将可执行的 PHP 文件直接上传到服务器，然后可以远程访问和执行这些文件以实现完全的系统入侵。  
  
只有当 WC Fields Factory 插件同时处于活动状态时，才能利用该漏洞，从而创建一个影响插件用户群子集的特定攻击媒介。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】全球互联网因BGP协议漏洞出现大规模路由震荡](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=1&sn=e29ae988e9c671b37c0b95f70beaf6d5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警惕！TikTok现新型"点击修复"骗局 黑客利用AI视频传播窃密木马](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=2&sn=72bc395534f95c110f7df164dcc3e50c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】数据泄露后阿迪达斯客户的个人信息面临风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=3&sn=632260e05f05720fa0ac3eee48933542&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Mac 用户遭围攻： 假账本应用程序通过恶意软件窃取加密秘密](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069865&idx=4&sn=e4a034c80ec818af36cf1f001b9f68b9&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
