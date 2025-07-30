#  AI自动挖洞不是梦，谷歌AI工具OSS-FASZ发现26个开源漏洞   
bug胤  FreeBuf   2024-11-22 11:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
谷歌透露，基于人工智能的模糊工具OSS-Fuzz 已被用于帮助识别各种开源代码库中的26个漏洞，包括 OpenSSL 加密库中的一个中度漏洞。这一事件代表了自动化漏洞发现的一个里程碑：每个漏洞都是使用AI发现的，利用AI生成和增强的模糊测试目标。  
  
  
提到的OpenSSL漏洞是CVE-2024-9143（CVSS评分：4.3），一个超出范围的内存写入缺陷，可能导致应用程序崩溃或远程代码执行。这个问题已经在OpenSSL的3.3.3、3.2.4、3.1.8、3.0.16、1.1.1zb和 1.0.2zl版本中得到了解决。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39G3iahheZOC71wg1O78CbDKE9xGM9wfdc0kRJox1A5E0zic7iczbbXK7PqBErKHq9IyYNnmhk4A9yCw/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**破题人类无法发现的漏洞**  
  
  
## 谷歌在2023年8月增加了利用大型语言模型（LLM）来提高OSS- Fuzz中模糊覆盖率的能力，并表示该漏洞可能在代码库中存在了20年，而且在现有的由人类编写的模糊目标中是无法发现的。此外，他们还指出，使用AI生成模糊测试目标已经提高了272个C/C++项目的代码覆盖率，新增了超过370,000行新代码。  
  
  
谷歌解释说，这样的漏洞之所以能够长时间未被发现，一个原因是线路覆盖率并不能保证函数没有漏洞。代码覆盖率作为一项指标，无法衡量所有可能的代码路径和状态，不同的标志和配置可能会触发不同的行为，从而暴露出不同的漏洞。这些人工智能辅助的漏洞发现也是可能的，因为LLMs被证明擅长模仿开发人员的模糊工作流程，从而允许更多的自动化。正如谷歌之前就提到过，其基于LLM的框架Big Sleep帮助发现SQLite开源数据库引擎中的一个零日漏洞。  
  
  
**C++代码安全性大幅提升**  
  
  
  
与此同时，谷歌一直在努力将自己的代码库转换为内存安全语言，如Rust，同时还对现有的C++项目（包括Chrome）中的空间内存安全漏洞（当代码可能访问超出其预定范围的内存时）进行改造。  
其中包括迁移到安全缓冲区和启用强化的libc ++，后者将边界检查添加到标准的 C ++数据结构中，以消除大量的空间安全缺陷。  
它进一步指出，纳入这一变化所产生的间接费用很小（即平均0.30%的绩效影响）。  
  
  
谷歌表示，由开源贡献者最近添加的“hardened libc++”引入了一系列安全检查，旨在捕获生产中的越界访问等漏洞。虽然C++不会完全成为内存安全的语言，但这些改进降低了风险，从而使得软件更加可靠和安全。  
  
  
具体来说，hardened libc++通过为标准C++数据结构添加边界检查来消除一大类空间安全漏洞。例如，hardened libc++确保对std::vector的每个元素的访问都保持在其分配的边界内，防止尝试读取或写入超出有效内存区域的尝试。同样，hardened libc++在允许访问之前检查std::optional是否为空，防止访问未初始化的内存。这种改进对于提高C++代码的安全性和可靠性具有重要意义。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://thehackernews.com/2024/11/googles-ai-powered-oss-fuzz-tool-finds.html  
  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651304667&idx=1&sn=d5cc3794a2a9b9626d688c709d261728&chksm=bd1c20508a6ba946471ea1bde2e433eea3f59aa89c656e5e95ac9d2d2a807abfecdca6773d07&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
