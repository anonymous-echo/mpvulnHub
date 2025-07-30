> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODY0NTczMA==&mid=2247493135&idx=1&sn=306bed2b9378881be53a5e8817b5691b

#  Forminator 插件漏洞使 WordPress 网站面临接管攻击  
Rhinoer  犀牛安全   2025-07-13 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBnQRYy4cNuk0aD1XGnLA2nmIyibmeKiaeeDU4VYH7gbichdFNXw7y9aQzJg96EpwCodwVvOArK4WWxgA/640?wx_fmt=png&from=appmsg "")  
  
WordPress 的 Forminator 插件存在未经身份验证的任意文件删除漏洞，可能导致整个站点接管攻击。  
  
该安全漏洞编号为 CVE-2025-6463，影响程度较高（CVSS 评分 8.8）。该漏洞影响 Forminator 1.44.2 及以上版本。  
  
Forminator Forms 是由 WPMU DEV 开发的插件。它提供了一个灵活、可视化的拖放构建器，帮助用户在 WordPress 网站上创建和嵌入各种基于表单的内容。  
  
根据 WordPress.org的统计，该插件目前在超过 600,000 个网站上活跃。  
  
该漏洞源于插件后端代码中对表单字段输入的验证和清理不足以及不安全的文件删除逻辑。  
  
当用户提交表单时，“save_entry_fields()”函数会保存所有字段值，包括文件路径，而不检查这些字段是否应该处理文件。  
  
攻击者可以利用此行为将精心设计的文件数组插入任何字段（包括文本字段），模仿上传的文件，并使用指向关键文件的自定义路径，例如“/var/www/html/wp-config.php”。  
  
当管理员删除此文件或插件自动删除旧提交（根据配置）时，Forminator 会擦除核心 WordPress 文件，迫使网站进入容易被接管的“设置”阶段。  
  
Wordfence 解释说：“删除 wp-config.php 会强制网站进入设置状态，从而允许攻击者通过将其连接到他们控制的数据库来启动网站接管。”  
  
发现和修补  
  
CVE-20256463 是由安全研究员“Phat RiO – BlueRock”发现的，他于 6 月 20 日向 Wordfence 报告了该漏洞，并获得了 8,100 美元的漏洞赏金。  
  
在对漏洞进行内部验证后，Wordfence 于 6 月 23 日联系了 WPMU DEV，后者确认了该报告并开始着手修复。  
  
6 月 30 日，该供应商发布了 Forminator 1.44.3 版本，该版本增加了字段类型检查和文件路径验证，以确保删除仅限于 WordPress 上传目录。  
  
自补丁发布以来，下载量已达 20 万次，但目前尚不清楚有多少次容易受到 CVE-2025-6463 漏洞的攻击。  
  
如果您在网站上使用 Forminator，建议将其更新到最新版本或停用该插件，直到您可以转移到安全版本。  
  
目前，尚无关于主动利用 CVE-2025-6463 的报告，但技术细节的公开披露加上利用的便利性可能导致威胁行为者迅速采取行动探索其攻击潜力。  
  
  
信息来源：  
BleepingComputer  
  
