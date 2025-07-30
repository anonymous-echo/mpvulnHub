#  src|拿下高危漏洞的秘诀？   
原创 simple学安全  simple学安全   2025-01-09 12:34  
  
免责声明：本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。  
  
前言  
  
挖掘src的过程中，我们会收集各种各样的资产信息，包括子域名、站点、URL信息等等。信息收集固然重要，但要挖掘出漏洞，更重要的是深入功能点，针对收集到的信息，有耐心地去过一遍各个功能点。  
  
接下来发现的这个高危漏洞就是，没有技巧，全是耐心。  
  
漏洞挖掘  
  
1、收集了一大堆资产后，开始了耐心的漏洞挖掘之旅，通过不断的访问各个功能点，在一个页面里面发现了一个不起眼的地方：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUichUraXZS3kKMPpLstCLz0piaia4jMmHHcDibdFibTwicWPpmFqr6GZ5Gz3NVic2G8JhZoOueAdEzvltdAQ/640?wx_fmt=png&from=appmsg "")  
  
左边是登录/注册，右边是详情  
  
2、当我点击详情时，得到了这个页面的作者邮箱  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUichUraXZS3kKMPpLstCLz0pyLtaCICdSZeQ6AiaJ96FdTchBG4mFN8DU8Svj7suHQqibemV7L1jQmbg/640?wx_fmt=png&from=appmsg "")  
  
3、当我点击登录/注册时，跳转到了登录页面，用户名可以是邮箱  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUichUraXZS3kKMPpLstCLz0pVI1IUdZmHpGDv4YFcHGyHLt0yzmdLpE1SF70t8PfhBZSeFoMllVSdQ/640?wx_fmt=png&from=appmsg "")  
  
4、这时候你可能会说我顶多是知道了用户名，没有密码顶什么用，但是当我点击注册新用户时，又有意想不到的收获，没有跳到常见的注册页面，直接给出了初始密码：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icjPTM4gYeUichUraXZS3kKMPpLstCLz0pn8yIMW5apVk3An96HIcUa027HCNNgexFOc9PwxuqZrwk6KNc5vdibVw/640?wx_fmt=jpeg&from=appmsg "")  
  
5、使用获得的邮箱和初始密码竟直接成功登录，原来是开发的记录文档  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUichUraXZS3kKMPpLstCLz0p8j8b3AdUb4TfhySIvkSc92S1C3pGpdqQh4SDKXEsZrEnSuhiax2CzIQ/640?wx_fmt=png&from=appmsg "")  
  
6、文档记录了一些网站的代码、数据库信息，提交之后直接定为高危漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUichUraXZS3kKMPpLstCLz0pI6W4YuqdM8spzm7L2gpokOe5QUQlmUmzoAdVnibBib8lV4VhAkjYHl2g/640?wx_fmt=png&from=appmsg "")  
  
7、就是这么简单，连包都没有抓一个，同时也让我意识到信息安全建设的不易，即使做了层层防护，多次测试，只要有一个疏漏，就可能出现安全事故。  
  
END  
  
查看更多精彩内容，关注  
simple学安全  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icjPTM4gYeU9knqRr6SqMfGqvUw1mPvauicyfafmT09zDhrasdngVtzibclFPMmiaXwxvYycfFHZmDsXtiaS5WJ9KEQ/640?wx_fmt=gif&from=appmsg "")  
  
