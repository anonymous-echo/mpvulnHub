#  （0day）某友CRM系统存在逻辑漏洞（大量资产存在）   
WebSec  白安全组   2024-01-03 13:59  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
    某友CRM系统是一款综合性的客户关系管理软件，旨在帮助企业建立和维护与客户之间的良好关系。它提供了全面的功能，包括销售管理、市场营销、客户服务和分析报告等。该系统支持多种行业和企业规模，并具有灵活可定制的特点，可以根据企业的需求进行个性化配置。该CRM系统软件存在逻辑漏洞，攻击者可利用此漏洞绕过登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QLhCeWibTBc2SlG5LGphUOu8rLwZQbniapT4mVZwLVrVG1ennwIO9wI6Tg/640?wx_fmt=png&from=appmsg "")  
  
**02**  
  
  
**资产测绘**  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QLQiaLkZ7teXwNsWvjjh2iaaFCNruBicKyYWhguRwn9j2ud5R1X4kTgKhVw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QL9hxbX56KQ4h1Zf6Oww39k0Kfx7DZKLxDroIOYPOypO77L5ibhKArKYw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QLOTHR8SQCpLJ3uicnEQYjSgGTcIKib8jn4dawdvydmOUB3KSpHZ8e56Ng/640?wx_fmt=png&from=appmsg "")  
访问此接口后，直接访问主页可直接绕过至后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QLtqdG5sKN85SdToqjquVyIVCA213YRVtjWHJiaBLQmTGicho4u9p55byw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**04**  
  
  
**修复建议**  
  
****  
****  
  
  
临时缓解方案：  
1. 加强访问控制和身份验证：对敏感操作和数据进行严格的访问控制和身份验证，只允许授权用户执行相应的操作。  
  
1. 检查网络连接：对与远程服务器的连接进行检查，避免存在未授权的连接，从而防止攻击者利用该漏洞进行攻击。  
  
1. 强化日志监控和审计：记录系统的操作日志和异常事件，及时发现异常行为和攻击迹象，以便及时采取相应的应对措施。  
  
升级修复方案：  
  
官方已发布安全更新，建议访问官网联系售后升级补丁  
  
  
  
**05**  
  
  
**星球介绍**  
  
  
1. 我们郑重承诺，每个工作日都会定时推送高质量的  
1day，有时也会分享未公开的  
0day。  
  
1. 新年活动期间，星球目前价格降至  
99元，等活动过后价格依旧为129元，报名人数满300人后，星球价格升至149元。  
  
1. 欢迎投稿  
最新漏洞poc或  
复现分析文章，符合条件的投稿者将获得一年免费会员资格。  
  
1. 公众号文章分享前五有现金红包奖励，  
第一名50，  
第二名40，依次排序，每  
半个月评选一次。  
  
1. 公众号主页添加微信，凭借公共号星标截图即可  
89元进入星球。  
  
1. ![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU8nMIO4COht96wJEibIUnJHtnsEkywnRfo0dsZRaOpUq1CVu0sxZ2UNOL6driat7a9qKQBfibIcv7VQ/640?wx_fmt=png&from=appmsg "")  
  
1. 星球新玩法：  
  
     1、  
每月星球成员积分前三(不包括星主、合伙人、嘉宾)可免费续费星球一年，次月再次排名前三额外奖励  
50RM  
B  
。  
  
      2、每月星球成员积分排名前10(不包括星主、合伙人)，并且发过三个有效主题(与安全相关内容)，月底结算积分(与  
人民币1比0.5  
结算,封顶100积分)。  
  
     3、凡是被定义成精华主题的，一条精华主题定价  
5元  
，不限月底积分排名，每个月仅有  
40条  
数量，越早发先定义，精华主题最终解释权归球主和合伙人所有，如果有师傅觉得发的主题可以定义为精华，可私聊球主商议。  
  
       4、老带新活动，凡是星球内部成功拉进星球的，拉进的新成员只需  
89元  
，此外拉的老成员将会获得  
19元  
红包奖励，上不封顶，此方式不支持退款，加入方式通过私聊星主。  
  
  
  
  
**更多漏洞poc发布在知识星球**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QL1VibBibQMk4EmfdOwgMnnzDapImjPlnWzEDnJ3Bv4gzuMVyFntSBoAUQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**漏洞复现专栏更新频率如下：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QLKdibvVuXysKJpV6Cx4pA3U7n0fpxrSxthbHRvFBicqicNicjEzFwV5xRFQ/640?wx_fmt=png&from=appmsg "")  
  
  
**星球专栏和最近部分主题的预览:**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCXGLwQtHsqdEZs6LBW1e5QL8SKfpLqrslNj9bKFNqibwvYlw1T0PiaRmx2UauYg0bKRRAeA01gylbRg/640?wx_fmt=jpeg&from=appmsg "")  
****  
  
****  
- END -  
  
  
  
