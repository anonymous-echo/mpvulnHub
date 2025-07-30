#  【0day】KingPortal运行系统信息泄露漏洞【未公开|附poc】   
原创 xiaocaiji  网安鲲为帝   2024-04-30 19:43  
  
**0x00****免责声明**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg "")  
  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
**0x01 漏洞描述**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VELYuopJicSQvd93eaKlOYkRRhic0TFfgERibjzJoOm6icCnu8S5EAEK9ia4RibPiba2IZPSqOJmkX9ju7TsQ/640?wx_fmt=png&from=appmsg "")  
  
随着工业互联网的迅速发展，传统的组态软件CS架构需要安装客户端、仅支持PC机、组态开发效率低、运行效果差等已满足不了市场需求。而目前工业监控领域的Web端产品，大多定制开发，维护难度大、周期长，需要工程师掌握高级语言，开发门槛高，不能有效解决Web和移动端的数据展示的综合问题。  
  
北京亚控科技发展有限公司自主研发的KingPortal是一款纯B/S架构面向工业监控领域的web端组态产品，是大数据可视化与工业互联网技术融合的产物，KingPortal以自动化技术为起点，以信息集成为突破口，以组件为基础进行Web端可视化组态开发，远超传统CS组态软件和其他Web端产品。KingPortal具备高质量Web界面、瘦客户端、跨平台兼容、免安装、低代码等核心技术优势。  
  
发现KingPortal运行系统存在未授权访问漏洞，泄露系统相关敏感信息，如id密钥等等，可能造成信息泄露后的未授权访问等严重危害，建议厂商尽快修复。  
  
**0x02 空间测绘**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg "")  
  
  
  
**搜索语句**  
  
**Hunter: web.similar_icon=="14138228322413032254"**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VELYuopJicSQvd93eaKlOYkRRW9M6eseMiap1iaGMuDJM5ibU9f3ic5UZU3qicQic2tGtK9LBSLHnSMZeSVIg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞复现**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg "")  
  
  
  
Get  
访问：  
/getConfigInfo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VELYuopJicSQvd93eaKlOYkRRJNH4nibTWrFTvEXpNToXfsxAnODDae7icIyLNNm1D02wIjyHu5bKQVnw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 修复意见**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg "")  
  
  
  
北京亚控科技发展有限公司自主研发的KingPortal是一款纯B/S架构面向工业监控领域的web端组态产品，是大数据可视化与工业互联网技术融合的产物，KingPortal以自动化技术为起点，以信息集成为突破口，以组件为基础进行Web端可视化组态开发，远超传统CS组态软件和其他Web端产品。KingPortal具备高质量Web界面、瘦客户端、跨平台兼容、免安装、低代码等核心技术优势。  
  
1、请联系厂商进行修复。   
  
2、如非必要，禁止公网访问该系统。   
  
3、设置白名单访问。  
  
  
**欢迎进群交流**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJdfiaGbzW6sp0kFvhYC7ejuJuS6lWyHyUGg40F2QVic6goic34EbYceQ2WE4eyMZ8oxbswQkhzJLhNQ/640?wx_fmt=jpeg&from=appmsg "")  
​  
  
