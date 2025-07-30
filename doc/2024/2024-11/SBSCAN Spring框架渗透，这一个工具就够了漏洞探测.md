#  SBSCAN Spring框架渗透，这一个工具就够了|漏洞探测   
 安全帮   2024-11-23 11:36  
  
0x01 工具介绍  
SBSCAN是一款专注于spring框架的渗透测试工具，可以对指定站点进行springboot未授权扫描/敏感信息扫描以及进行spring相关漏洞的扫描与验证。  
  
  
**下载地址在末尾**  
  
0x02 功能简介核心特性最全的敏感路径字典：最全的springboot站点敏感路径字典，帮你全面检测站点是否存在敏感信息泄漏支持指纹检测：支持spring站点指纹匹配：支持启用指纹识别，只有存在spring指纹的站点才进行下一步扫描，节约资源与时间 (无特征的站点会漏报，客官自行决策是否启用)支持敏感路径页面关键词指纹匹配：通过维护敏感路径包含的关键词特征，对检出的页面进行指纹匹配，大大提升了工具检出的准确率，减少了人工去确认敏感页面真实性投入的时间支持指定模块发起检测： 不想跑漏洞，只想检测敏感路径？或者只想检测漏洞？都可以，通过 -m 参数指定即可最全的spring漏洞检测POC：spring相关cve漏洞的检测poc全部给你集成到这款工具里，同类型最全无回显漏洞解决： 无回显漏洞检测扫描器光看响应状态码不太靠谱？支持--dnslog参数指定dnslog域名，看到dnslog记录才是真的成功验证漏洞存在。降噪输出结果： 可通过指定-q参数只显示成功的检测结果友好的可扩展性： 项目设计初期就考虑了用户的自定义扩展需求，整个项目尽量采用高内聚低耦合模块化的编程方式， 你可轻松的加上自己的poc、日常积累的敏感路径、绕过语句，轻松优化检测逻辑，具体见下文的“自定义扩展”。其他一些常规支持：单个url扫描/ url文件扫描 / 扫描模块选择 / 支持指定代理 / 支持多线程 / 扫描报告生成。检测效果图, 使用彩色表格打印更直观显示检测结果，检测报告保存位置将会在扫描结束后控制台显示检测时可使用 tail -f logs/sbscan.log 实时查看详细的检测情况0x03更新说明将扫描管理、路径探测、指纹检测和 CVE 探测的相关的调度与管理模块进行优化处理、对程序进一步解耦提升代码的可读性和可维护性本次对程序所有脚本新增了全局的会话复用、多线程管理等优化，增加了程序稳定性和扫描性能新增JeeSpringCloud 2023 任意文件上传漏洞检测采用正则进行匹配优化，优化了url、代理格式检测、自动修正url格式的逻辑代理支持指定单个、多个、文件的方式进行配置0x04 使用介绍MacOS && linux下载SBSCAN解压$ cd SBSCAN$ python3 -m venv sbscan         # 创建虚拟环境$ source sbscan/bin/activate     # 激活虚拟环境$ pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple   # -i 指定pip源安装依赖,可选；$ python3 sbscan.py --helpWindows下载SBSCAN解压$ cd SBSCAN$ python3 -m venv sbscan         # 创建虚拟环境$ .\sbscan\Scripts\activate        # 激活虚拟环境$ pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple   # -i 指定pip源安装依赖,可选；$ python3 sbscan.py --help命令说明-u, --url                              对单个URL进行扫描-f, --file                             读取文件中的url目标进行扫描-m, --mode                             指定扫描模式[path/cve/all],默认all-p, --proxy                            指定HTTP代理-t, --threads                          指定线程数量-q, --quiet                            启用纯净输出,只输出命中的敏感路径信息-ff, --fingerprint_filter              启用指纹检测,只扫描命中指纹的站点(可能有漏报，结合实际情况选择是否启用)-d, --dnslog                           指定DNSLog域名,用于检测到无回显漏洞时可接收被攻击主机的dns请求--help                                 显示帮助信息Example# 指定目标站点url进行扫描$ python3 sbscan.py -u http://test.com# 指定url文件路径扫描，启用指纹检测，未检测到指纹的无需进行路径以及CVE扫描$ python3 sbscan.py -f url.txt --ff# 仅对目标进行漏洞扫描并且只输出命中的cve$ python3 sbscan.py -f url.txt -m cve --quiet# 指定目标站点url、代理、线程数量$ python3 sbscan.py -u http://test.com -p 1.1.1.1:8888 -t 10# 指定目标站点url、启用纯净输出，只输出命中敏感路径或cve的目标、启用指纹检测，只有命中指纹的才继续扫描$ python3 sbscan.py -u http://test.com --quiet -ff# 指定url文件路径、指定dnslog域名、使用10个线程进行并发扫描并启用纯净输出$ python3 sbscan.py -f url.txt -t 4 -d 5pugcrp1.eyes.sh --quiet  
  
**0x04 项目地址**  
  
  
  
https://github.com/sule01u/SBSCAN  
  
  
  
