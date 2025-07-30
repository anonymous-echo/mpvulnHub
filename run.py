# -*- coding: utf-8 -*-
import os
import re
import sys
import json
import xml.etree.ElementTree as ET
import platform
import tempfile
import requests
import shutil
import subprocess
import datetime
import argparse
import glob
import calendar
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('run.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)


def write_json(path, data, encoding="utf8"):
    """写入json"""
    with open(path, "w", encoding=encoding) as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def read_json(path, default_data={}, encoding="utf8"):
    """读取json"""
    data = {}
    if os.path.exists(path):
        try:
            data = json.loads(open(path, "r", encoding=encoding).read())
        except:
            data = default_data
            write_json(path, data, encoding=encoding)

    else:
        data = default_data
        write_json(path, data, encoding=encoding)
    return data

def get_executable_path():
    '''获取可执行文件路径'''
    system = platform.system()
    if system == 'Windows':
        executable_path = './bin/wechatmp2markdown-v1.1.11_win64.exe'
    else:
        executable_path = './bin/wechatmp2markdown-v1.1.11_linux_amd64'
    # 添加执行权限
    os.chmod(executable_path, 0o755)
    # 返回可执行文件的完整路径
    return executable_path

def get_md_path(executable_path,url):
    '''获取md文件路径'''
    temp_directory = tempfile.mkdtemp()
    command = [executable_path, url, temp_directory, '--image=url']
    subprocess.check_output(command)
    for root, _, files in os.walk(temp_directory):
        for file in files:
            if file.endswith(".md"):
                file_path = os.path.join(root, file)
                yield file_path



def get_doonsec_url(target_date=None):
    '''从 Doonsec RSS 获取指定日期的URL、日期和标题，返回(url, date, title)元组列表'''
    logger.info("开始获取Doonsec RSS")
    if target_date:
        logger.info(f"目标日期: {target_date}")
    
    cookies = {
        'UM_follow': 'True',
        'UM_distinctids': 'fgmr',
        'session': 'eyJfcGVybWFuZW50Ijp0cnVlLCJjc3JmX3Rva2VuIjoiMzU2ZDE4OTcwZjliZDljY2NjN2M3YzlkMzRhOGVlZWQyZDk1NmI1ZSIsInZpc3RvciI6ImZHTXJGQXBlVndRUnZrWjJHdWplV2gifQ.ZzidRw.GyjS15N12JYU0TByO31rrwBIiPY',
    }
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    }
    try:
        response = requests.get('https://wechat.doonsec.com/rss.xml', cookies=cookies, headers=headers)
        response.encoding = response.apparent_encoding
        logger.info("Doonsec RSS请求成功")
        root = ET.fromstring(response.text)
        url_date_title_list = []
        total_items = len(root.findall('./channel/item'))
        logger.info(f"RSS中共有 {total_items} 个条目")
        
        for item in root.findall('./channel/item'):
            title = item.findtext('title') or ''
            link = item.findtext('link') or ''
            pub_date = item.findtext('pubDate') or ''
            date_str = ''
            if pub_date:
                try:
                    date_str = pub_date[:10]
                    logger.debug(f"解析日期: {pub_date} -> {date_str}")
                except:
                    date_str = ''
            
            # 如果指定了目标日期，则只返回该日期的文章
            if target_date and date_str != target_date:
                logger.debug(f"跳过非目标日期的文章: {date_str} != {target_date}")
                continue
            
            # 只检查是否为微信链接，不进行关键词过滤
            if link.startswith('https://mp.weixin.qq.com/'):
                url_date_title_list.append((link.rstrip(')'), date_str, title))
                logger.debug(f"获取到文章: {title} -> {link} (日期: {date_str})")
        
        if target_date:
            logger.info(f"Doonsec获取到 {len(url_date_title_list)} 个{target_date}的微信文章URL")
        else:
            logger.info(f"Doonsec获取到 {len(url_date_title_list)} 个微信文章URL")
        return url_date_title_list
    except Exception as e:
        logger.error(f"Doonsec RSS解析失败: {e}")
        return []

def parse_md_urls_with_title(md_text):
    """
    解析md文件，返回[(url, title)]
    支持- [标题](url)、* [标题](url)、1. [标题](url)等格式
    """
    pattern = re.compile(r'^[\-\*\d\. ]+\[(.*?)\]\((https://mp.weixin.qq.com/[^)\s]+)\)', re.MULTILINE)
    return [(m.group(2), m.group(1)) for m in pattern.finditer(md_text)]

def filter_by_keywords(urls_info):
    """
    根据关键词过滤文章，只保留安全相关的文章
    """
    # 通过AI分析，将所有关键词按功能领域分类
    keywords = [
        # ===== 漏洞利用与攻击技术 =====
        '复现', '漏洞', '漏洞利用', '漏洞挖掘', '漏洞检测', '漏洞分析', '漏洞修复', '漏洞防护',
        '漏洞扫描', '漏洞评估', '漏洞管理', '漏洞响应', '漏洞预警', '漏洞通报',
        'SQL注入', 'XSS攻击', 'CSRF攻击', '文件上传', '文件包含', '命令注入',
        '代码注入', '反序列化', '缓冲区溢出', '权限提升', '越权访问', '未授权访问',
        '逻辑漏洞', '配置错误', '弱口令', '默认密码', '硬编码', '敏感信息泄露',
        '注入', 'XSS', '内网', '域控', 'RCE', '代码执行', '命令执行',
        '远程代码执行', '本地代码执行', '权限绕过', '信息泄露', '拒绝服务',
        '内存破坏', '整数溢出', '格式化字符串', '竞争条件', '时间竞争',
        '路径遍历', '目录遍历', '文件包含', '命令注入', '代码注入',
        
        # ===== 威胁情报与APT =====
        '威胁情报', '威胁检测', '威胁狩猎', '威胁分析', '威胁建模', '威胁评估', '威胁预警',
        '情报收集', '情报分析', '情报共享', '情报平台', '情报系统', '情报运营',
        '恶意软件', '恶意代码', '恶意行为', '恶意活动', '恶意攻击', '恶意威胁',
        'APT攻击', 'APT组织', 'APT活动', 'APT威胁', 'APT检测', 'APT分析',
        '威胁情报平台', '威胁情报系统', '威胁情报分析', '威胁情报共享',
        
        # ===== 应急响应与溯源 =====
        '应急响应', '安全响应', '事件响应', '应急处理', '应急管理', '应急演练',
        '溯源分析', '攻击溯源', '威胁溯源', '恶意代码溯源', '网络溯源', '数字取证',
        '取证分析', '证据收集', '证据保全', '证据链', '时间线分析', '攻击链分析',
        '威胁狩猎', '威胁追踪', '威胁定位', '威胁识别', '威胁分类', '威胁评估',
        '安全事件', '安全告警', '安全日志', '安全监控', '安全检测', '安全分析',
        
        # ===== 安全运营与管理 =====
        '安全运营', '安全运维', '安全管理', '安全治理', '安全合规', '安全审计',
        '安全监控', '安全分析', '安全评估', '安全测试', '安全培训', '安全意识',
        '安全架构', '安全设计', '安全开发', '安全部署', '安全配置', '安全策略',
        '安全控制', '安全防护', '安全检测', '安全响应', '安全恢复', '安全备份',
        '安全日志', '安全事件', '安全告警', '安全报告', '安全指标', '安全度量',
        '安全工具', '安全平台', '安全系统', '安全服务', '安全咨询', '安全外包',
        '安全团队', '安全专家', '安全工程师', '安全分析师', '安全管理员',
        '漏洞运营', 'SRC', '安全运营框架', '安全治理框架',
        
        # ===== 红队蓝队与攻防演练 =====
        '红队', '蓝队', '紫队', '攻防演练', '渗透测试', '安全评估',
        '漏洞扫描', '安全测试', '安全审计', '安全评估', '风险评估',
        
        # ===== 特定攻击技术与恶意软件 =====
        '社会工程学', '钓鱼攻击', '水坑攻击', '供应链攻击', '零日攻击',
        '侧信道攻击', '中间人攻击', '拒绝服务', '分布式拒绝服务', 'DDoS',
        '勒索软件', '木马', '后门', '病毒', '蠕虫', '僵尸网络', '银狐',
        
        # ===== 漏洞编号与标准 =====
        'CVE-', 'CNVD-', 'CNNVD-', 'XVE-', 'QVD-', 'POC', 'EXP', '0day', '1day', 'nday',
        'CWE-', 'ISO27001', 'NIST', 'OWASP', 'CIS', 'SOC', 'SIEM', 'SOAR',
        '威胁情报标准', '安全运营框架', '安全治理框架',
        
        # ===== 数据安全与隐私 =====
        '信息泄漏', '数据泄露', '隐私泄露', '数据安全', '隐私保护',
        '身份认证', '访问控制', '会话管理', '加密算法', '加密协议', '数字签名',
        '证书管理', '密钥管理', '密码学', '密码破解', '多因子认证', '单点登录',
        
        # ===== 云安全与新兴技术 =====
        '云安全', '容器安全', 'DevSecOps', '云原生安全', '微服务安全',
        '区块链安全', '人工智能安全', '机器学习安全', '深度学习安全',
        '量子计算威胁', 'AI安全威胁', '5G安全威胁', '边缘计算安全',
        '零信任架构', '微分段', '微隔离', '自适应安全', '智能安全',
        
        # ===== 应用与系统安全 =====
        '应用安全', 'Web安全', '移动安全', 'Web应用安全', '移动应用安全', 'API安全',
        'Windows安全', 'Linux安全', 'macOS安全', 'Android安全', 'iOS安全',
        
        # ===== 行业与基础设施安全 =====
        '物联网安全', '工业安全', '供应链安全', '金融安全', '医疗安全', '教育安全',
        '政府安全', '企业安全', '关键基础设施安全', '工业控制系统安全', '智能电网安全',
        
        # ===== 安全工具与技术 =====
        '防火墙', '入侵检测', '入侵防护', '安全网关', 'VPN', '加密',
        '审计日志', '安全扫描', '漏洞扫描', '渗透测试', '代码审计', '安全评估'
    ]
    
    filtered_urls = []
    skipped_count = 0
    
    for url, source, title, date in urls_info:
        if not title:
            continue
            
        title_lower = title.lower()
        matched = False
        
        for keyword in keywords:
            if keyword.lower() in title_lower:
                filtered_urls.append((url, source, title, date))
                logger.debug(f"关键词匹配: {keyword} -> {title}")
                matched = True
                break
        
        if not matched:
            logger.debug(f"关键词不匹配，跳过: {title}")
            skipped_count += 1
    
    logger.info(f"关键词过滤: 匹配 {len(filtered_urls)} 个，跳过 {skipped_count} 个")
    return filtered_urls

def process_one_day(date_str, doonsec_list, chainreactors_urls, brucefeiix_urls, data, data_file, base_result_path, executable_path, skip_binary=False):
    # 1. 先去重，收集所有待处理信息（带标题）
    logger.info(f"=== 开始处理 {date_str} 的数据 ===")
    logger.info(f"Doonsec原始数据: {len(doonsec_list)} 个")
    logger.info(f"ChainReactors原始数据: {len(chainreactors_urls)} 个")
    logger.info(f"BruceFeIix原始数据: {len(brucefeiix_urls)} 个")
    
    urls_info = []
    url_set = set()
    skipped_count = 0
    
    # Doonsec
    logger.info("开始处理Doonsec数据...")
    for url, ddate, title in doonsec_list:
        use_date = ddate if ddate else date_str
        if url in data or url in url_set:
            logger.debug(f"跳过已存在的URL: {url}")
            skipped_count += 1
            continue
        urls_info.append((url, "Doonsec", title, use_date))
        url_set.add(url)
        logger.debug(f"添加Doonsec URL: {url}")
    
    # ChainReactors
    logger.info("开始处理ChainReactors数据...")
    for url, title in chainreactors_urls:
        if url in data or url in url_set:
            logger.debug(f"跳过已存在的URL: {url}")
            skipped_count += 1
            continue
        urls_info.append((url, "ChainReactors", title, date_str))
        url_set.add(url)
        logger.debug(f"添加ChainReactors URL: {url}")
    
    # BruceFeIix
    logger.info("开始处理BruceFeIix数据...")
    for url, title in brucefeiix_urls:
        if url in data or url in url_set:
            logger.debug(f"跳过已存在的URL: {url}")
            skipped_count += 1
            continue
        urls_info.append((url, "BruceFeIix", title, date_str))
        url_set.add(url)
        logger.debug(f"添加BruceFeIix URL: {url}")
    
    logger.info(f"去重后共 {len(urls_info)} 个URL待处理，跳过 {skipped_count} 个重复URL")
    
    # 按数据源统计
    doonsec_count = len([u for u in urls_info if u[1] == "Doonsec"])
    chainreactors_count = len([u for u in urls_info if u[1] == "ChainReactors"])
    brucefeiix_count = len([u for u in urls_info if u[1] == "BruceFeIix"])
    logger.info(f"去重后统计 - Doonsec: {doonsec_count} 个, ChainReactors: {chainreactors_count} 个, BruceFeIix: {brucefeiix_count} 个")
    
    # 2. 关键词过滤
    logger.info("=== 开始关键词过滤 ===")
    urls_info = filter_by_keywords(urls_info)
    
    # 过滤后按数据源统计
    doonsec_count = len([u for u in urls_info if u[1] == "Doonsec"])
    chainreactors_count = len([u for u in urls_info if u[1] == "ChainReactors"])
    brucefeiix_count = len([u for u in urls_info if u[1] == "BruceFeIix"])
    logger.info(f"关键词过滤后统计 - Doonsec: {doonsec_count} 个, ChainReactors: {chainreactors_count} 个, BruceFeIix: {brucefeiix_count} 个")
    
    # 3. 先生成当日md报告（标题和链接同步）
    if urls_info:
        create_daily_md_report(date_str, urls_info)
    
    if skip_binary:
        # 跳过二进制文件处理，只更新data.json
        logger.info("=== 跳过二进制文件处理，只更新data.json ===")
        added_count = 0
        for idx, (url, source, title, article_date) in enumerate(urls_info):
            if not title:
                # 如果没有标题，使用URL作为标题
                title = f"微信文章_{idx+1}"
            
            # 再次检查URL是否已在data.json中存在
            if url in data:
                logger.debug(f"跳过已存在于data.json的URL: {url}")
                continue
                
            # 直接更新data.json，不调用二进制文件
            data[url] = title
            added_count += 1
            logger.debug(f"更新data.json: {url} -> {title}")
        
        # 保存data.json
        write_json(data_file, data)
        logger.info(f"已更新data.json，添加了 {added_count} 个URL")
    else:
        # 4. 再批量抓取和归档
        for idx, (url, source, title, article_date) in enumerate(urls_info):
            real_title = save_md_and_update_data(url, article_date, base_result_path, data, data_file, executable_path, source, article_date)
            if not title:
                urls_info[idx] = (url, source, real_title, article_date)
    
    # 5. 最后再补全md报告（带真实标题）
    if urls_info:
        create_daily_md_report(date_str, urls_info)



    
def rep_filename(result_path):
    ''' 
    替换不能用于文件名的字符
    '''
    for root, _, files in os.walk(result_path):
        for file in files:
            if file.endswith(".md"):
                file_path = os.path.join(root, file)
                new_file = re.sub(r'[\/\\\:\*\?\"\<\>\|]', '', file)
                shutil.move(os.path.join(root, file), os.path.join(root, new_file))
                

def extract_title_from_md(md_path):
    # 尝试从md文件首行获取标题，否则用文件名
    try:
        with open(md_path, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            if first_line.startswith('#'):
                return first_line.lstrip('#').strip()
    except:
        pass
    return os.path.splitext(os.path.basename(md_path))[0]

def analyze_security_threats(urls_info):
    """
    分析安全威胁态势
    """
    threat_categories = {
        '漏洞利用': ['CVE', 'CNVD', 'CNNVD', 'XVE', 'QVD', 'POC', 'EXP', '0day', '1day', 'nday', '漏洞', '复现'],
        '攻击技术': ['注入', 'XSS', 'RCE', '代码执行', '命令执行', '内网', '域控'],
        '威胁情报': ['威胁情报', 'APT', '银狐', '勒索病毒', '应急响应'],
        '安全运营': ['安全运营', '漏洞运营', '情报运营', 'SRC'],
        '信息泄露': ['信息泄漏', '数据泄露', '配置泄露'],
        '供应链': ['供应链', '第三方', '组件']
    }
    
    threat_stats = {category: 0 for category in threat_categories.keys()}
    threat_details = {category: [] for category in threat_categories.keys()}
    
    for url, source, title, date in urls_info:
        if not title:
            continue
        title_lower = title.lower()
        for category, keywords in threat_categories.items():
            for keyword in keywords:
                if keyword.lower() in title_lower:
                    threat_stats[category] += 1
                    threat_details[category].append((title, source, url))
                    break
    
    return threat_stats, threat_details

def analyze_vulnerability_types(urls_info):
    """
    分析漏洞类型分布
    """
    vuln_types = {
        'Web安全': ['SQL注入', 'XSS', 'CSRF', '文件上传', '文件包含', '命令注入'],
        '系统漏洞': ['RCE', '权限提升', '缓冲区溢出', '内核漏洞'],
        '应用漏洞': ['反序列化', '逻辑漏洞', '配置错误', '弱口令'],
        '网络攻击': ['钓鱼', '社会工程学', 'APT', '勒索软件'],
        '供应链': ['第三方组件', '开源漏洞', '依赖注入']
    }
    
    vuln_stats = {vuln_type: 0 for vuln_type in vuln_types.keys()}
    
    for url, source, title, date in urls_info:
        if not title:
            continue
        title_lower = title.lower()
        for vuln_type, keywords in vuln_types.items():
            for keyword in keywords:
                if keyword.lower() in title_lower:
                    vuln_stats[vuln_type] += 1
                    break
    
    return vuln_stats

def create_daily_md_report(date_str, urls_info, md_dir="md"):
    """
    创建每日md报告文档
    urls_info: [(url, source, title, date), ...]
    """
    os.makedirs(md_dir, exist_ok=True)
    
    # 文件名格式：2025-07-25.md
    filename = f"{date_str}.md"
    filepath = os.path.join(md_dir, filename)
    
    # 统计信息
    total_urls = len(urls_info)
    sources = {}
    for _, source, _, _ in urls_info:
        sources[source] = sources.get(source, 0) + 1
    
    # 安全威胁分析
    threat_stats, threat_details = analyze_security_threats(urls_info)
    vuln_stats = analyze_vulnerability_types(urls_info)
    
    # MD模板
    md_content = f"""# {date_str} 安全威胁态势报告

## 📊 数据概览

- **总文章数**: {total_urls}
- **数据源分布**:
"""
    
    for source, count in sources.items():
        md_content += f"  - {source}: {count}篇\n"
    
    md_content += f"""
## 🚨 安全威胁态势分析

### 威胁类型分布
"""
    
    # 按威胁数量排序
    sorted_threats = sorted(threat_stats.items(), key=lambda x: x[1], reverse=True)
    for threat_type, count in sorted_threats:
        if count > 0:
            md_content += f"- **{threat_type}**: {count}篇\n"
    
    md_content += f"""
### 漏洞类型分析
"""
    
    # 按漏洞数量排序
    sorted_vulns = sorted(vuln_stats.items(), key=lambda x: x[1], reverse=True)
    for vuln_type, count in sorted_vulns:
        if count > 0:
            md_content += f"- **{vuln_type}**: {count}篇\n"
    
    md_content += f"""
## 🔍 匹配规则

### 关键词匹配规则

#### 🔍 漏洞利用与攻击技术
`复现|漏洞|漏洞利用|漏洞挖掘|漏洞检测|漏洞分析|漏洞修复|漏洞防护|漏洞扫描|漏洞评估|漏洞管理|漏洞响应|漏洞预警|漏洞通报|SQL注入|XSS攻击|CSRF攻击|文件上传|文件包含|命令注入|代码注入|反序列化|缓冲区溢出|权限提升|越权访问|未授权访问|逻辑漏洞|配置错误|弱口令|默认密码|硬编码|敏感信息泄露|注入|XSS|内网|域控|RCE|代码执行|命令执行|远程代码执行|本地代码执行|权限绕过|信息泄露|拒绝服务|内存破坏|整数溢出|格式化字符串|竞争条件|时间竞争|路径遍历|目录遍历|文件包含|命令注入|代码注入`

#### 🕵️ 威胁情报与APT
`威胁情报|威胁检测|威胁狩猎|威胁分析|威胁建模|威胁评估|威胁预警|情报收集|情报分析|情报共享|情报平台|情报系统|情报运营|恶意软件|恶意代码|恶意行为|恶意活动|恶意攻击|恶意威胁|APT攻击|APT组织|APT活动|APT威胁|APT检测|APT分析|威胁情报平台|威胁情报系统|威胁情报分析|威胁情报共享`

#### 🚨 应急响应与溯源
`应急响应|安全响应|事件响应|应急处理|应急管理|应急演练|溯源分析|攻击溯源|威胁溯源|恶意代码溯源|网络溯源|数字取证|取证分析|证据收集|证据保全|证据链|时间线分析|攻击链分析|威胁狩猎|威胁追踪|威胁定位|威胁识别|威胁分类|威胁评估|安全事件|安全告警|安全日志|安全监控|安全检测|安全分析`

#### 🛡️ 安全运营与管理
`安全运营|安全运维|安全管理|安全治理|安全合规|安全审计|安全监控|安全分析|安全评估|安全测试|安全培训|安全意识|安全架构|安全设计|安全开发|安全部署|安全配置|安全策略|安全控制|安全防护|安全检测|安全响应|安全恢复|安全备份|安全日志|安全事件|安全告警|安全报告|安全指标|安全度量|安全工具|安全平台|安全系统|安全服务|安全咨询|安全外包|安全团队|安全专家|安全工程师|安全分析师|安全管理员|漏洞运营|SRC|安全运营框架|安全治理框架`

#### ⚔️ 红队蓝队与攻防演练
`红队|蓝队|紫队|攻防演练|渗透测试|安全评估|漏洞扫描|安全测试|安全审计|安全评估|风险评估`

#### 🦠 特定攻击技术与恶意软件
`社会工程学|钓鱼攻击|水坑攻击|供应链攻击|零日攻击|侧信道攻击|中间人攻击|拒绝服务|分布式拒绝服务|DDoS|勒索软件|木马|后门|病毒|蠕虫|僵尸网络|银狐`

#### 📋 漏洞编号与标准
`CVE-|CNVD-|CNNVD-|XVE-|QVD-|POC|EXP|0day|1day|nday|CWE-|ISO27001|NIST|OWASP|CIS|SOC|SIEM|SOAR|威胁情报标准|安全运营框架|安全治理框架`

#### 🔐 数据安全与隐私
`信息泄漏|数据泄露|隐私泄露|数据安全|隐私保护|身份认证|访问控制|会话管理|加密算法|加密协议|数字签名|证书管理|密钥管理|密码学|密码破解|多因子认证|单点登录`

#### ☁️ 云安全与新兴技术
`云安全|容器安全|DevSecOps|云原生安全|微服务安全|区块链安全|人工智能安全|机器学习安全|深度学习安全|量子计算威胁|AI安全威胁|5G安全威胁|边缘计算安全|零信任架构|微分段|微隔离|自适应安全|智能安全`

#### 💻 应用与系统安全
`应用安全|Web安全|移动安全|Web应用安全|移动应用安全|API安全|Windows安全|Linux安全|macOS安全|Android安全|iOS安全`

#### 🏭 行业与基础设施安全
`物联网安全|工业安全|供应链安全|金融安全|医疗安全|教育安全|政府安全|企业安全|关键基础设施安全|工业控制系统安全|智能电网安全`

#### 🛠️ 安全工具与技术
`防火墙|入侵检测|入侵防护|安全网关|VPN|加密|审计日志|安全扫描|漏洞扫描|渗透测试|代码审计|安全评估`

### URL匹配
`https://mp.weixin.qq.com/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*]|(?:%[0-9a-fA-F][0-9a-fA-F]))+`

## 📰 文章详细列表

"""
    
    # 按来源分组
    source_groups = {}
    for url, source, title, article_date in urls_info:
        if source not in source_groups:
            source_groups[source] = []
        source_groups[source].append((url, title, article_date))
    
    for source, articles in source_groups.items():
        md_content += f"### {source}\n\n"
        for url, title, article_date in articles:
            date_info = f" (发布日期: {article_date})" if article_date else ""
            md_content += f"- [{title}]({url}){date_info}\n"
        md_content += "\n"
    
    # 威胁详情
    md_content += f"""
## 🎯 威胁详情分析

"""
    
    for threat_type, articles in threat_details.items():
        if articles:
            md_content += f"### {threat_type}\n\n"
            md_content += "| 序号 | 文章标题 | 来源 | 链接 |\n"
            md_content += "|------|----------|------|------|\n"
            for idx, (title, source, url) in enumerate(articles, 1):
                md_content += f"| {idx} | {title} | {source} | [{url}]({url}) |\n"
            md_content += "\n"
    
    md_content += f"""
## 📁 归档路径

文章已归档到: `doc/{date_str[:4]}/{date_str[:7]}/{date_str[:4]}-W{datetime.datetime.strptime(date_str, '%Y-%m-%d').isocalendar()[1]:02d}/{date_str}/`

## 🔗 数据源说明

- **ChainReactors**: GitHub安全文章聚合，专注于漏洞复现和技术分析
- **BruceFeIix**: 安全文章收集，涵盖威胁情报和安全运营
- **Doonsec**: 安全资讯RSS，实时推送安全事件和漏洞预警

## 📈 趋势分析

### 今日重点关注
"""
    
    # 找出今日最热门的威胁类型
    if threat_stats:
        top_threat = max(threat_stats.items(), key=lambda x: x[1])
        md_content += f"- **{top_threat[0]}** 是今日主要威胁类型，共 {top_threat[1]} 篇相关文章\n"
    
    # 找出今日最热门的漏洞类型
    if vuln_stats:
        top_vuln = max(vuln_stats.items(), key=lambda x: x[1])
        md_content += f"- **{top_vuln[0]}** 是今日主要漏洞类型，共 {top_vuln[1]} 篇相关文章\n"
    
    md_content += f"""
### 安全建议
- 及时关注高危漏洞的修复进展
- 加强供应链安全管理
- 定期进行安全培训和意识提升
- 建立完善的安全运营体系

---
*生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*报告工具: 微信文章安全归档系统*
"""
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(md_content)
    
    logger.info(f"已创建每日报告: {filepath}")
    return filepath

def save_md_and_update_data(url, date_str, base_result_path, data, data_file, executable_path, source="未知", article_date=None):
    logger.info(f"开始处理URL: {url}")
    logger.info(f"目标日期: {date_str}")
    logger.info(f"数据源: {source}")
    
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    year = dt.year
    month = dt.strftime('%Y-%m')
    week = f"{year}-W{dt.isocalendar()[1]:02d}"
    day = dt.strftime('%Y-%m-%d')
    result_path = os.path.join(base_result_path, str(year), month, week, day)
    
    logger.info(f"生成目录结构: {result_path}")
    os.makedirs(result_path, exist_ok=True)
    
    title = "未知标题"
    for file_path in get_md_path(executable_path, url):
        filename = os.path.basename(file_path)
        logger.info(f"处理文件: {filename}")
        
        if filename == '.md':
            logger.warning(f"跳过空文件: {filename}")
            continue
            
        shutil.copy2(file_path, result_path)
        logger.info(f"文件已复制到: {result_path}")
        
        # 获取标题
        title = extract_title_from_md(file_path)
        logger.info(f"提取标题: {title}")
        
        # 保存标题到data.json
        data[url] = title
        write_json(data_file, data)
        logger.info(f"已更新data.json: {url} -> {title}")
        
        print(title, end='、')
    
    rep_filename(result_path)
    logger.info(f"完成处理URL: {url}")
    
    return title

def get_chainreactors_md_url(date_str):
    """
    获取指定日期的ChainReactors每日md文件URL
    """
    return f'https://raw.githubusercontent.com/chainreactors/picker/refs/heads/master/archive/daily/{date_str[:4]}/{date_str}.md'

def get_BruceFeIix_md_url(date_str):
    """
    获取指定日期的BruceFeIix每日md文件URL
    """
    return f'https://raw.githubusercontent.com/BruceFeIix/picker/refs/heads/master/archive/daily/{date_str[:4]}/{date_str}.md'

def main():
    '''主函数'''
    logger.info("=== 开始执行微信文章归档工具 ===")
    
    parser = argparse.ArgumentParser(description='微信文章批量归档工具')
    parser.add_argument('--history', action='store_true', help='拉取历史记录')
    parser.add_argument('--date', type=str, help='指定日期，格式YYYY-MM-DD')
    parser.add_argument('--range', nargs=2, metavar=('START', 'END'), help='指定日期区间，格式YYYY-MM-DD YYYY-MM-DD')
    parser.add_argument('--skip-binary', action='store_true', help='跳过二进制文件处理流程，只更新data.json')
    args = parser.parse_args()

    data_file = 'data.json'
    data = {}
    executable_path = get_executable_path()
    base_result_path = 'doc'

    logger.info(f"数据文件: {data_file}")
    logger.info(f"可执行文件: {executable_path}")
    logger.info(f"文档目录: {base_result_path}")

    # 读取历史记录
    data = read_json(data_file, default_data=data)
    logger.info(f"已加载 {len(data)} 条历史记录")

    if args.history:
        logger.info("=== 开始历史记录拉取 ===")
        start_date = '2022-04-07'
        end_date = datetime.datetime.now().strftime('%Y-%m-%d')
        start = datetime.datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.datetime.strptime(end_date, "%Y-%m-%d")
        current_date = start
        logger.info(f"历史拉取范围: {start_date} 到 {end_date}")
        while current_date <= end:
            date_str = current_date.strftime('%Y-%m-%d')
            local_path = os.path.join('archive', 'daily', date_str[:4], f"{date_str}.md")
            logger.debug(f"检查本地文件: {local_path}")
            doonsec_list = []
            chainreactors_urls = []
            brucefeiix_urls = []
            if os.path.exists(local_path):
                with open(local_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                urls = re.findall(r'(https://mp.weixin.qq.com/[\w\-\?&=%.]+)', content, re.I)
                urls = [url.rstrip(')') for url in urls]
                chainreactors_urls = urls
            try:
                process_one_day(date_str, doonsec_list, chainreactors_urls, brucefeiix_urls, data, data_file, base_result_path, executable_path, args.skip_binary)
            except Exception as e:
                logger.error(f"处理日期 {date_str} 时发生错误: {e}")
                logger.error("跳过当前日期的处理")
            current_date += datetime.timedelta(days=1)
    elif args.date:
        logger.info(f"=== 开始指定日期拉取: {args.date} ===")
        date_str = args.date
        doonsec_list = get_doonsec_url(date_str)  # [(url, date, title)]
        # ChainReactors
        chainreactors_urls = []
        cr_md_url = get_chainreactors_md_url(date_str)
        logger.info(f"ChainReactors md文件URL: {cr_md_url}")
        if cr_md_url:
            try:
                resp = requests.get(cr_md_url)
                logger.info(f"ChainReactors md文件下载状态码: {resp.status_code}")
                if resp.status_code == 200:
                    chainreactors_urls = parse_md_urls_with_title(resp.text)
                    logger.info(f"ChainReactors获取到 {len(chainreactors_urls)} 个URL")
                else:
                    logger.warning(f"ChainReactors md文件下载失败: {cr_md_url} 状态码: {resp.status_code}")
            except Exception as e:
                logger.error(f"ChainReactors md解析失败: {e}")
        else:
            logger.warning("ChainReactors md文件URL为空")
        # BruceFeIix
        brucefeiix_urls = []
        bf_md_url = get_BruceFeIix_md_url(date_str)
        logger.info(f"BruceFeIix md文件URL: {bf_md_url}")
        if bf_md_url:
            try:
                resp = requests.get(bf_md_url)
                logger.info(f"BruceFeIix md文件下载状态码: {resp.status_code}")
                if resp.status_code == 200:
                    brucefeiix_urls = parse_md_urls_with_title(resp.text)
                    logger.info(f"BruceFeIix获取到 {len(brucefeiix_urls)} 个URL")
                else:
                    logger.warning(f"BruceFeIix md文件下载失败: {bf_md_url} 状态码: {resp.status_code}")
            except Exception as e:
                logger.error(f"BruceFeIix md解析失败: {e}")
        else:
            logger.warning("BruceFeIix md文件URL为空")
        try:
            process_one_day(date_str, doonsec_list, chainreactors_urls, brucefeiix_urls, data, data_file, base_result_path, executable_path, args.skip_binary)
        except Exception as e:
            logger.error(f"处理日期 {date_str} 时发生错误: {e}")
            logger.error("跳过当前日期的处理")
    elif args.range:
        logger.info(f"=== 开始日期区间拉取: {args.range[0]} 到 {args.range[1]} ===")
        start, end = args.range
        start_dt = datetime.datetime.strptime(start, "%Y-%m-%d")
        end_dt = datetime.datetime.strptime(end, "%Y-%m-%d")
        current_date = start_dt
        
        # 统计区间内的总天数
        total_days = (end_dt - start_dt).days + 1
        processed_days = 0
        
        while current_date <= end_dt:
            processed_days += 1
            date_str = current_date.strftime('%Y-%m-%d')
            logger.info(f"=== 处理第 {processed_days}/{total_days} 天: {date_str} ===")
            
            # 获取指定日期的Doonsec数据
            doonsec_list = get_doonsec_url(date_str)
            
            # ChainReactors
            chainreactors_urls = []
            cr_md_url = get_chainreactors_md_url(date_str)
            logger.info(f"ChainReactors md文件URL: {cr_md_url}")
            if cr_md_url:
                try:
                    resp = requests.get(cr_md_url)
                    logger.info(f"ChainReactors md文件下载状态码: {resp.status_code}")
                    if resp.status_code == 200:
                        chainreactors_urls = parse_md_urls_with_title(resp.text)
                        logger.info(f"ChainReactors获取到 {len(chainreactors_urls)} 个URL")
                    else:
                        logger.warning(f"ChainReactors md文件下载失败: {cr_md_url} 状态码: {resp.status_code}")
                except Exception as e:
                    logger.error(f"ChainReactors md解析失败: {e}")
            else:
                logger.warning("ChainReactors md文件URL为空")
            
            # BruceFeIix
            brucefeiix_urls = []
            bf_md_url = get_BruceFeIix_md_url(date_str)
            logger.info(f"BruceFeIix md文件URL: {bf_md_url}")
            if bf_md_url:
                try:
                    resp = requests.get(bf_md_url)
                    logger.info(f"BruceFeIix md文件下载状态码: {resp.status_code}")
                    if resp.status_code == 200:
                        brucefeiix_urls = parse_md_urls_with_title(resp.text)
                        logger.info(f"BruceFeIix获取到 {len(brucefeiix_urls)} 个URL")
                    else:
                        logger.warning(f"BruceFeIix md文件下载失败: {bf_md_url} 状态码: {resp.status_code}")
                except Exception as e:
                    logger.error(f"BruceFeIix md解析失败: {e}")
            else:
                logger.warning("BruceFeIix md文件URL为空")
            
            # 处理当前日期的数据
            try:
                process_one_day(date_str, doonsec_list, chainreactors_urls, brucefeiix_urls, data, data_file, base_result_path, executable_path, args.skip_binary)
                logger.info(f"=== 完成第 {processed_days}/{total_days} 天处理 ===")
            except Exception as e:
                logger.error(f"=== 第 {processed_days}/{total_days} 天处理失败: {e} ===")
                logger.error(f"跳过 {date_str} 的处理，继续下一个日期")
            
            current_date += datetime.timedelta(days=1)
    else:
        logger.info("=== 开始今日拉取 ===")
        current_date = datetime.datetime.now()
        date_str = current_date.strftime('%Y-%m-%d')
        doonsec_list = get_doonsec_url(date_str)
        # ChainReactors
        chainreactors_urls = []
        cr_md_url = get_chainreactors_md_url(date_str)
        logger.info(f"ChainReactors md文件URL: {cr_md_url}")
        if cr_md_url:
            try:
                resp = requests.get(cr_md_url)
                logger.info(f"ChainReactors md文件下载状态码: {resp.status_code}")
                if resp.status_code == 200:
                    chainreactors_urls = parse_md_urls_with_title(resp.text)
                    logger.info(f"ChainReactors获取到 {len(chainreactors_urls)} 个URL")
                else:
                    logger.warning(f"ChainReactors md文件下载失败: {cr_md_url} 状态码: {resp.status_code}")
            except Exception as e:
                logger.error(f"ChainReactors md解析失败: {e}")
        else:
            logger.warning("ChainReactors md文件URL为空")
        # BruceFeIix
        brucefeiix_urls = []
        bf_md_url = get_BruceFeIix_md_url(date_str)
        logger.info(f"BruceFeIix md文件URL: {bf_md_url}")
        if bf_md_url:
            try:
                resp = requests.get(bf_md_url)
                logger.info(f"BruceFeIix md文件下载状态码: {resp.status_code}")
                if resp.status_code == 200:
                    brucefeiix_urls = parse_md_urls_with_title(resp.text)
                    logger.info(f"BruceFeIix获取到 {len(brucefeiix_urls)} 个URL")
                else:
                    logger.warning(f"BruceFeIix md文件下载失败: {bf_md_url} 状态码: {resp.status_code}")
            except Exception as e:
                logger.error(f"BruceFeIix md解析失败: {e}")
        else:
            logger.warning("BruceFeIix md文件URL为空")
        try:
            process_one_day(date_str, doonsec_list, chainreactors_urls, brucefeiix_urls, data, data_file, base_result_path, executable_path, args.skip_binary)
        except Exception as e:
            logger.error(f"处理日期 {date_str} 时发生错误: {e}")
            logger.error("跳过当前日期的处理")
    logger.info("=== 执行完成 ===")

if __name__ == '__main__':
    main()
