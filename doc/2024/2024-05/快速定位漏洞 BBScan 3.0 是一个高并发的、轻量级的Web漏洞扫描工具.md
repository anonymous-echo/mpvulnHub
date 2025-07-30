#  快速定位漏洞 BBScan 3.0 是一个高并发的、轻量级的Web漏洞扫描工具   
原创 lijiejie  网安守护   2024-05-28 17:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/cm9mPvQVqibGMBVHPR8piaic1b1vW3wjJL5kFweluCUnzPogkNnVnbMTBgOPWjjwBwVPYlXB36WXibJTT2vXVzGIZw/640?wx_fmt=png&from=appmsg "")  
  
  
BBScan 是一个高并发的、轻量级的Web漏洞扫描工具。它帮助安全工程师从大量目标中，快速发现，定位可能存在弱点的目标，辅助半自动化测试。  
  
BBScan is a fast and light-weight web vulnerability scanner. It helps pen-testers pinpoint possibly vulnerable targets from a large number of web servers.  
- Scan common web vulnerabilities: **Data Leaks** / **Directory Traversal** /  **Admin Backends**  
  
- Extract **API Endpoints** from .js file, Scan **Token/Secrets/Pass/Key Leaks**  
  
- Recognize **Web Fingerprints**: web frameworks, programming languages, CMS,  middle-ware, open source software or commercial product name  
  
### Test Reports  
  
Brute sub names for *.baidu.com *.qq.com *.bytedance.com with subDomainsBrute and then  
  
send the output files to BBScan,  scan reports are as shown below  
- qq.com_report.html  
  
- bytedance.com_report.html  
  
- baidu.com_report.html  
  
### Install  
  
Require Python 3.6+  
```
pip3 install -r requirements.txt

resource


```  
```
https://github.com/lijiejie/BBScan
```  
```
```  
- **2024-05-27**  
  
- CMS识别功能，Web指纹来自 FingerprintHub  Credit to @0x727  
  
- JavaScript解析支持，提取拼接API接口，支持检测Key/Secret/Token泄露  
  
- 通过正则表达式提取URL，From: https://github.com/Threezh1/JSFinder  Credit to @Threezh1  
  
- **New Features**：  
  
- **减少漏报**：优化减少DNS查询次数，提高稳定性  
  
- **减少误报**：优化了误报验证逻辑  
  
- ``**界面优化**：输出更加易用的Web报告  
  
### Usage  
- ##### Scan from file  
  
  
```
python BBScan.py -f urls.txt --api
```  
- **Scan from command line**  
  
```
python BBScan.py --host www.test.com https://test2.com http://test3.com:8080 10.1.2.3
```  
- ##### Scan with specified rules only  
  
  
```
python BBScan.py --rule git_and_svn -f urls.txt
```  
### Key Arguments  
- --network MASK  
  
You scan involve other IPs under the same network to a scan  
  
- --host www.baidu.com --network 24  
  
- -f urls.txt --network 28  
  
- --fp, --fingerprint  
  
Under this mode, only fingerprint scan performed only, this helps to save some time by disable rule/script based scan.  
  
- --api  
  
Gather and display all API interfaces extracted from .js file  
  
- --skip, --skip-intranet  
  
Skip scanning private IP targets.  
  
```
	usage: BBScan.py [options]	Targets:	  --host [HOST [HOST ...]]	                        Scan several hosts from command line	  -f TargetFile         Load new line delimited targets from TargetFile	  -d TargetDirectory    Load all *.txt files from TargetDirectory	  --crawler CrawlDirectory	                        Load all *.log crawl files from CrawlDirectory	  --network MASK        Scan all Target/MASK neighbour hosts,	                        should be an integer between 8 and 31	  --skip, --skip-intranet	                        Do not scan private IPs, when you are not under the same network with the target	Rule Based SCAN:	  --rule [RuleFileName [RuleFileName ...]]	                        Import specified rule files only.	  -n, --no-crawl        No crawling, sub folders will not be processed	  --no-check404         No HTTP 404 existence check	  --full                Process all sub directories	  --fp, --fingerprint   Disable rule and script scan, only check fingerprint	Script Based SCAN:	  --scripts-only        Scan with user scripts only	  --script [ScriptName [ScriptName ...]]	                        Execute specified scripts only	  --no-scripts          Disable all scripts	CONCURRENT:	  -p PROCESS            Num of processes running concurrently, 30 by default	  -t THREADS            Num of scan threads for each scan process, 3 by default	OTHER:	  --proxy Proxy         Set HTTP proxy server	  --timeout Timeout     Max scan minutes for each target, 10 by default	  --api                 Gather and display all API interfaces extracted from .js file	  --save-ports PortsDataFile	                        Save open ports to PortsDataFile	  --debug               Show verbose debug info	  --no-browser          Do not open web browser to view report	
	usage: BBScan.py [options]



	Targets:

	  --host [HOST [HOST ...]]
	                        Scan several hosts from command line
	  -f TargetFile         Load new line delimited targets from TargetFile
	  -d TargetDirectory    Load all *.txt files from TargetDirectory
	  --crawler CrawlDirectory
	                        Load all *.log crawl files from CrawlDirectory
	  --network MASK        Scan all Target/MASK neighbour hosts,
	                        should be an integer between 8 and 31
	  --skip, --skip-intranet
	                        Do not scan private IPs, when you are not under the same network with the target

	Rule Based SCAN:

	  --rule [RuleFileName [RuleFileName ...]]
	                        Import specified rule files only.
	  -n, --no-crawl        No crawling, sub folders will not be processed
	  --no-check404         No HTTP 404 existence check
	  --full                Process all sub directories
	  --fp, --fingerprint   Disable rule and script scan, only check fingerprint

	Script Based SCAN:

	  --scripts-only        Scan with user scripts only
	  --script [ScriptName [ScriptName ...]]
	                        Execute specified scripts only
	  --no-scripts          Disable all scripts

	CONCURRENT:

	  -p PROCESS            Num of processes running concurrently, 30 by default
	  -t THREADS            Num of scan threads for each scan process, 3 by default

	OTHER:

	  --proxy Proxy         Set HTTP proxy server
	  --timeout Timeout     Max scan minutes for each target, 10 by default
	  --api                 Gather and display all API interfaces extracted from .js file
	  --save-ports PortsDataFile
	                        Save open ports to PortsDataFile
	  --debug               Show verbose debug info
	  --no-browser          Do not open web browser to view report
	
```  
  
  
**推荐书籍**  
  
  
  
  
  
**历史文章**  
  
[人 生](http://mp.weixin.qq.com/s?__biz=MzU4NDY3MTk2NQ==&mid=2247489841&idx=1&sn=d2507a5b9d29fad53817748d3a9c18ea&chksm=fd976e83cae0e795c86c622e91e0e248488d08d5d35fb900c91dd768a6e921ed97760e8d140f&scene=21#wechat_redirect)  
  
  
[有一个问题 AI人工智能时代 到底我们需要学什么](http://mp.weixin.qq.com/s?__biz=MzU4NDY3MTk2NQ==&mid=2247489893&idx=1&sn=fedb1b099e63585afda89adb64d6b34a&chksm=fd976ed7cae0e7c1138b23f8cfecc1a3dd786feb57d9639aebf8a00ae43b1b16cce6d4fcb944&scene=21#wechat_redirect)  
  
  
[回味先前的精彩文章 回首过往发生的事情](http://mp.weixin.qq.com/s?__biz=MzU4NDY3MTk2NQ==&mid=2247489772&idx=1&sn=0473354e625616e4eb0ff68f849c9653&chksm=fd976f5ecae0e648db6f129ca883ed8ec2ac0166ad0668082be7f6cd89242e01491cc13c11d8&scene=21#wechat_redirect)  
  
  
  
  
  
