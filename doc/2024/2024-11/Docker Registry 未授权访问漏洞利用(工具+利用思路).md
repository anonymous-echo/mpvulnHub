#  Docker Registry 未授权访问漏洞利用(工具+利用思路)   
原创 黑熊先生  黑熊安全   2024-11-30 07:09  
  
亲爱的读者，我们诚挚地提醒您，黑熊安全公众号的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。黑熊安全团队及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
#### 漏洞描述  
  
Docker Registry 未授权访问指的是由于 Docker Registry 私有仓库搭建  
以后默认其他所有客户端均可以 push、pull 镜像， 如果不设置用户认证方法来对 Docker 仓库进行权限保护，对 Docker Registry 中的数据安全造成隐患。该漏洞会导致 Docker 服务器的数据被泄漏、篡改和删除，配置文件被修改，甚至通过提权来控制服务器，危害十分严重。  
  
默认服务端口是5000  
  
漏洞api  
  
http://x.x.x.x/v2/_catalog  
  
访问页面样例如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3ksUjsr0vMWjns2b51hPBMPvZfkTlSFwy26tGRABm1SfhdYK5eSx9u9A/640?wx_fmt=png&from=appmsg "")  
  
使用工具docker_v2_downlod.py可以下载出镜像  
  
下载地址：https://pan.quark.cn/s/d2e81315e6e4  
  
使用命令  
  
python docker_v2_downlod.py -u http://x.x.x.x  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kX7DSALj3vLs3eMqwQ0AyBX0Iqpf2jJk5ST7IXDl0ZgXOh8ALRY58kg/640?wx_fmt=png&from=appmsg "")  
  
然后复制你想要下载的哪个镜像  
  
选择下载的版本等待下载完成。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3k8XY8PyH405Vpwia6vIRWKiaYHODWJyBg2TJRZ1ic0MzxOBhqk7IICG7ng/640?wx_fmt=png&from=appmsg "")  
  
常规利用思路如下  
  
思路1：  
  
找到jar包解压，找到配置文件，里面大概率有账号密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kbAoy3GXEFfTp60maCFXEHicDr021X3lg7r3MKE6exSy26N34TGTu3Uw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kVQRSHO6fictITzs2osQuIhZv47mVrpWfl2XotFyTIBVleXshBXOkOwQ/640?wx_fmt=png&from=appmsg "")  
  
进入到BOOT-INF  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kEnicwYXlyr9dsUk2aorFQAVDopq6lca8CRUIibN2dIQHnasHshhAfkqQ/640?wx_fmt=png&from=appmsg "")  
  
进入到classes  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kFgw1ib0UYzPfib4V2A2HHh0pTNcwwFnGle4qyJglezmyiceInSrv1gaxQ/640?wx_fmt=png&from=appmsg "")  
  
翻后缀是properties文件里面都是配置信息。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kUtWV0H5X4llVRKlTfSbxPP5QqXhuhVIHRzpsN7eKNJDvNp9dz1qia0g/640?wx_fmt=png&from=appmsg "")  
  
思路2：  
  
思路1的操作如果没有翻取到敏感文件，建议直接使用searchall工具  
  
下载地址：https://pan.quark.cn/s/527174cb0679  
  
工具作用：  
searchall3.5可以快速搜索服务器中的有关username，passsword,账号，口令的敏感信息还有浏览器的账户密码。(这个工具常常被利用再攻防中，上传到沦陷主机一键搜索账号密码使用)  
  
利用命令：searchall64_upx.exe search -p 路径  
  
样例  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kRdTDdicCOeyp32HBP26FYpaZXUokXTQicL2pYkWTEG9dE35WhUx253fQ/640?wx_fmt=png&from=appmsg "")  
  
search.txt存着他能找到的账号密码，aksk等数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wVib8wlRwspCibibVnsucMegB3kLI3Y0TcUMvFjibLlOQuGQlJa4gUjnibiaARKSkrNuGibGknC9H2VgFYAzw/640?wx_fmt=png&from=appmsg "")  
  
已发布文章所有下载工具连接：https://pan.quark.cn/s/0c1cbe67aec4  
  
承接SRC众测、网站众测、红蓝攻防、代码审计、培训、公众号广告等业务。微信：xxbearyyds  
  
