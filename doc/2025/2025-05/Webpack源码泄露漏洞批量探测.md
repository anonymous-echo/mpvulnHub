#  Webpack源码泄露漏洞批量探测   
回忆潋红雨  神农Sec   2025-05-16 02:23  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
原文链接：  
https://xz.aliyun.com/news/17972  
  
作者：  
回忆潋红雨  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**Webpack漏洞测试**  
  
# 一、漏洞原理  
  
  
Webpack 源码泄露漏洞是一种由于前端打包工具 Webpack 配置不当，导致攻击者可通过 .map 文件还原原始源代码的安全风险。  
  
  
Webpack 在打包前端项目时，若开启 source map 生成功能（如配置 devtool: "source-map"），会生成 .js.map 文件或内嵌映射信息到 JS 文件中。  
  
  
- Source map 作用：用于生产环境调试，将压缩/混淆后的代码映射回原始源码，便于定位错误。  
- 泄露途径  
- 显式生成 .map 文件：当 devtool 设为 source-map、hidden-source-map 等值时，JS 文件同级目录会生成 .map 文件，通过直接访问 main.js.map 即可下载；  
- 内嵌映射信息：当 devtool 设为 inline-source-map 时，映射数据会以 Base64 形式内嵌在 JS 文件末尾。  
# 二、漏洞危害  
  
  
泄露的源码可能包含以下敏感信息，导致进一步攻击：  
  
  
- 业务逻辑暴露：API 接口路径、权限验证逻辑、加密算法（如登录密码加解密方式）；  
- 敏感数据泄露：管理员邮箱、内网 IP 地址、数据库连接配置（若开发阶段未删除测试配置）；  
- 攻击面扩大：还原后的代码可辅助挖掘 XSS、越权访问等漏洞。  
# 三、漏洞检测  
  
1. 浏览器插件检测  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWN8lCEKibLtKAicHib2Ko76dktSkXUeslIO45NToeqxltiaUAfL79icxpXgKWZPiadC6qlriaLRaBRF9X7w/640?wx_fmt=png&from=appmsg "")  
  
1. F12搜索关键字  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWN8lCEKibLtKAicHib2Ko76dk2vcgGHROZvtsHHFOGReecnicP3ZpYvyj60o1tZJMsEdHksE6CUgRJmg/640?wx_fmt=png&from=appmsg "")  
  
1. 批量探测  
- 获取HTML页面  
- 解析JS文件链接  
- 并发检测JS文件  
- 特征检测  
- 版本检测  
- SourceMap检测  
- 输出CSV/HTML文件  
```
import requests
import re
import csv
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()


def detect_webpack(domain):
    """
    检测域名是否使用Webpack打包器
    返回：域名, [检测结果列表]
    """
    domain = domain.strip()
    if not domain:
        return (domain, [])

    detected_data = []

    try:
        # 获取HTML页面
        response = requests.get(
            f"https://{domain}",
            timeout=15,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if response.status_code != 200:
            return (domain, [])

        # 解析JS文件链接
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script', {'src': True})
        js_urls = list({urljoin(response.url, tag['src']) for tag in script_tags})  # 去重

        # 并发检测JS文件
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_js_file, url) for url in js_urls]
            for future, url in zip(futures, js_urls):
                result = future.result()
                if result["detected"]:
                    detected_data.append({
                        "js_url": url,
                        "version": result["version"],
                        "sourcemap": result["sourcemap"],
                        "patterns": result["patterns"]
                    })

        return (domain, detected_data)

    except Exception as e:
        return (domain, [])


def check_js_file(url):
    """
    检查JS文件特征并返回完整检测数据
    返回：{
        "detected": bool,
        "version": str,
        "sourcemap": str,
        "patterns": list,
        "js_url": str
    }
    """
    result = {
        "detected": False,
        "version": None,
        "sourcemap": None,
        "patterns": [],
        "js_url": url
    }

    try:
        # 下载前100KB内容
        headers = {'Range': 'bytes=0-102400', 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(
            url,
            timeout=10,
            verify=False,
            headers=headers,
            stream=True
        )
        content = response.text.lower()

        # 特征检测
        patterns = {
            '__webpack_require__': '核心函数标识',
            'webpackchunk': '代码分块特征',
            'webpackjsonp': '异步加载标识',
            '[contenthash]': '文件哈希命名规则'
        }

        # 匹配特征
        matched_patterns = []
        for pattern, desc in patterns.items():
            if re.search(pattern, content):
                matched_patterns.append(f"{desc}({pattern})")

        # 版本检测
        version_match = re.search(r'webpack\s+v?(\d+\.\d+\.\d+)', content)
        if version_match:
            result["version"] = version_match.group(1)

        # SourceMap检测
        sourcemap_match = re.search(r'//# sourceMappingURL=(.+\.map)', content)
        if sourcemap_match:
            result["sourcemap"] = urljoin(url, sourcemap_match.group(1))

        # 综合判断
        if matched_patterns or result["version"] or result["sourcemap"]:
            result.update({
                "detected": True,
                "patterns": matched_patterns
            })

        return result

    except Exception as e:
        return result


def generate_html_report(csv_path, html_path):
    """生成带样式的HTML报告"""
    # 读取CSV数据
    df = pd.read_csv(csv_path)

    # 生成HTML表格
    html = df.to_html(index=False, escape=False)

    # 添加CSS样式
    styled_html = f"""
    <html>
        <head>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
                }}
                th {{
                    background-color: #4CAF50;
                    color: white;
                    padding: 12px;
                    text-align: left;
                }}
                td {{
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                tr:hover {{
                    background-color: #ddd;
                }}
                .detected {{
                    color: green;
                    font-weight: bold;
                }}
                .sourcemap {{
                    max-width: 300px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }}
            </style>
        </head>
        <body>
            <h2>Webpack检测报告</h2>
            {html}
        </body>
    </html>
    """

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(styled_html)


def process_domains(input_file, output_csv, output_html):
    # 读取域名列表
    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # 并发处理
    results = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(detect_webpack, domain) for domain in domains]
        for future in futures:
            results.append(future.result())

    # 写入CSV文件
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Domain',
            'Webpack Detected',
            'JS Path',
            'Detected Patterns',
            'Webpack Version',
            'SourceMap URL'
        ])

        for domain, files in results:
            if files:
                for data in files:
                    writer.writerow([
                        domain,
                        'True',
                        data["js_url"],
                        '; '.join(data["patterns"]),
                        data["version"] or 'N/A',
                        data["sourcemap"] or 'N/A'
                    ])
            else:
                writer.writerow([domain, 'False', 'N/A', 'N/A', 'N/A', 'N/A'])

    # 生成HTML报告
    generate_html_report(output_csv, output_html)


if __name__ == "__main__":
    process_domains(
        input_file="domains.txt",
        output_csv="webpack_report.csv",
        output_html="webpack_report.html"
    )
```  
- 结果呈现  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWN8lCEKibLtKAicHib2Ko76dkftHkwA0ibWJKlQiafuBglt0OswicMDX8NxHolZMlXAyCibah3MMv82kqwg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWN8lCEKibLtKAicHib2Ko76dk0ibolwsLlibDsAFBZ2941AxJHVdt8wzFKedwSYj1ICic4S1u4IvPqOXhA/640?wx_fmt=png&from=appmsg "")  
  
# 四、漏洞利用  
  
  
本文重点是漏洞的批量探测，关于漏洞利用手法不过多赘述，下文仅列举常见的攻击手法。  
  
  
1. 下载 .map 文件：通过上述方法获取目标网站的 .map 文件；  
1. 还原源码：使用 reverse-sourcemap 工具还原原始项目结构：  
```
npm install -g reverse-sourcemap
reverse-sourcemap --output-dir ./src main.js.map
```  
  
还原后的代码将保留原始目录结构（如 Vue 组件的 assets、router 目录）  
  
1. 分析敏感信息：重点检查 config/（配置）、api/（接口）、utils/（通用函数）等目录  
# 五、修复方案  
  
  
- 禁用 source map 生成：在生产环境配置中设置 productionSourceMap: false（Vue 项目修改 vue.config.js）或 devtool: false（Webpack 原生配置）；  
- 删除已有 .map 文件：通过服务器配置（如 Nginx）禁止访问 .map 文件，或直接移除部署目录中的 .map 文件；  
- 代码混淆加固：使用 terser-webpack-plugin 等工具对 JS 代码进行深度混淆，增加逆向难度；  
- 内网信息审查：确保源码中不包含测试环境的内网 IP、硬编码凭证等敏感数据。  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**内部圈子详情介绍**  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQrFWcBesgFeibmAaLTXbl25YKcjTuT0F7X8qBLgI7JaOjU1DxsgxfyicbBDibicKwvIhjia1Jm33NQaA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWVBja0AC9744PeXY0zNUj3v6KmOYGICdhjhFw8L88cnT1OrpYgNicV4aoMewFjsYU10dia4BvkUibg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
#   
  
