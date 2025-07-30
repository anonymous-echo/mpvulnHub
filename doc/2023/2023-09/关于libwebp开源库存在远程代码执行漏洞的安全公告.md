#  关于libwebp开源库存在远程代码执行漏洞的安全公告   
 网络安全应急技术国家工程中心   2023-09-29 11:08  
  
安全公告编号:CNTA-2023-0016  
  
2023年9月27日，国家信息安全漏洞共享平台（CNVD）收录了libwebp开源库远程代码执行漏洞（  
CNVD-2023-73247  
，对应CVE-2023-5129、CVE-2023-4863）。攻击者利用该漏洞可以在目标主机设备执行任意代码或敏感信息未授权访问。目前，该漏洞的利用细节和测试代码已公开，开源库厂商已发布新版本完成修复。CNVD建议受漏洞影响的产品（服务）厂商、信息系统运营者和用户尽快进行修复。  
  
**一、漏洞情况分析**  
  
WebP是Google公司开发的一种图像格式，支持网络图像的有损和无损压缩，其压缩效果和速度较PNG和JPEG格式具有一定优势。libwebp是实现WebP图像格式编解码的C/C++开源库。libwebp通过提供功能函数和系列工具，可将图像数据编码为WebP格式，以及将WebP格式图像进行解码还原。libwebp也可作为依赖库，实现程序对WebP图像格式的支持。libwebp在容器镜像、框架、浏览器、Linux操作系统和应用程序等具有较多应用。  
  
近日，Google公司发布安全公告修复了libwebp开源库远程代码执行漏洞。libwebp的BuildHuffmanTable函数在使用霍夫曼算法（Huffman）对Webp图片进行解码时，由于缺少必要的输入验证，存在内存越界写入缺陷。未经身份认证的攻击者通过制作恶意页面或文件，诱导用户浏览访问执行越界内存写入，实现对目标主机设备的远程任意代码执行或者敏感信息未授权访问。该漏洞在某些环境条件下可被实现零点击利用（0-Click）。  
  
CNVD对该漏洞的综合评级为“高危”。  
  
**二、漏洞影响范围**  
  
该漏洞影响的产品和版本为：  
  
使用libwebp（低于1.3.2版本）处理WebP格式图像的框架、软硬件产品（服务）和信息系统。  
  
目前，已知受该漏洞影响的产品和框架包括：  
  
Google Chrome for Mac/Linux < 116.0.5845.187  
  
Google Chrome for Windows < 116.0.5845.187/.188  
  
Mozilla Firefox < 117.0.1  
  
Microsoft Edge < 109.0.1518.140, 116.0.1938.81, 117.0.2045.31  
  
Electron < 22.3.24, 24.8.3, 25.8.1, 26.2.1,
27.0.0-beta.2  
  
  
**三、漏洞处置建议**  
  
目前，Google公司及受影响的产品（服务）厂商已陆续发布新版本修复该漏洞。CNVD建议受漏洞影响的产品（服务）厂商、信息系统运营者和用户尽快进行自查，及时进行版本更新和漏洞修复：  
  
https://storage.googleapis.com/downloads.webmproject.org/releases/webp/index.html  
  
https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4863  
  
https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/  
  
https://github.com/electron/electron/pull/39828  
  
  
  
参考链接：  
  
https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/  
  
https://support.apple.com/en-us/HT213905  
  
https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html  
  
https://www.accessnow.org/publication/hacking-meduza-pegasus-spyware-used-to-target-putins-critic/  
  
https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html  
  
https://stackdiary.com/heap-buffer-overflow-in-libwebp-cve-2023-5129/  
  
https://chromium.googlesource.com/webm/libwebp/+/2af26267cdfcb63a88e5c74a85927a12d6ca1d76  
  
https://chromium.googlesource.com/webm/libwebp/+/902bc9190331343b2017211debcec8d2ab87e17a  
  
  
感谢北京神州绿盟科技有限公司、奇安信网神信息技术（北京）股份有限公司和北京微步在线科技有限公司为本报告提供的技术支持。  
  
  
