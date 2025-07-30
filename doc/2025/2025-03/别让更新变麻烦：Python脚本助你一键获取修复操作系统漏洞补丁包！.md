#  别让更新变麻烦：Python脚本助你一键获取修复操作系统漏洞补丁包！   
原创 didiplus  攻城狮成长日记   2025-03-02 07:18  
  
   
  
> 字数 1430，阅读大约需 8 分钟  
  
  
在日常工作中，服务器安全是企业运营的关键。我们专业的安全团队会用工具对所有服务器进行扫描，找出潜在的安全问题，并生成详细的报告，里面不仅有漏洞信息，还有修复建议。如下图所示，这样不仅能及时解决问题，还能帮助企业建立更安全的防护体系，保障业务正常运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYs3ibJOqFcXy179icWZk246uUnAEtQmqzeibxF6OdppITz0Z5dF8XVOLric901lF7MQ44nwKwhsjKN22A/640?wx_fmt=png&from=appmsg "null")  
  
  
**那问题来了**  
，虽然表格中提供了每个漏洞的修复建议链接，但还是需要我们逐一访问官方页面来详细了解具体的修复方案。当漏洞数量较少时，这项工作还算轻松；但如果数量较多，那这个任务的工作量确实会变得相当大。  
  
像这种重复的工作肯定是交给脚本去执行的。我们现来分析一下，我们最终想要实现的效果，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYs3ibJOqFcXy179icWZk246uUpg5HMbOGpl8qs8NuTVqbia5v80g8nhTpVblLfcyg838RGqm72LFDROw/640?wx_fmt=png&from=appmsg "null")  
  
## 实现思路  
- • 我们将利用Python  
中的pandas  
库来处理原始数据，以CVE  
编号作为主要标识符，并把具有相同CVE  
编号的所有主机信息整理在一起。  
  
- • 对于修复步骤，您可以通过访问官方提供的修复链接，根据页面上的关键词找到需要更新的具体软件包。之后，可以根据这些信息构建出使用yum  
命令进行更新的具体指令。  
  
## 代码实现  
### 获取更新软件包  
  
我们首先分析一下如果从**官方修复方案**  
的中提取需要修复软件包，以CVE-2020-24370  
这个漏洞为例，打开**官方修复方案**  
的链接，页面如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYs3ibJOqFcXy179icWZk246uUqHoPOlMuLa5GaCicY9OT6qC5DY42zyYXGicrHSiczKNxrAbqe6zBn7VOg/640?wx_fmt=png&from=appmsg "null")  
  
  
从上图可以看出，修复的软件包有一个共同的特点：它们都遵循“包名-版本号_ky10  
”这样的命名格式。基于这一点，我们可以使用正则表达式来匹配这些软件包。  
  
下面是一个示例函数，它可以从指定的网页中提取出更新的软件包信息。这个函数的工作流程是这样的：首先接收一个URL  
作为参数，然后利用Python  
的第三方库requests  
获取该网页的内容，最后通过正则表达式筛选出我们需要的软件包列表。  
```
def get_kylin_patches(url):    # 设置请求头模拟浏览器访问    headers = {        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'    }    try:        response = requests.get(url, timeout=10,headers=headers)        response.raise_for_status()                soup = BeautifulSoup(response.text, 'html.parser')        # 获取所有base-desc容器        desc_containers = soup.find_all('div', class_='base-desc')        # 只提取第二个base-desc内容（索引从0开始）        packages_list = []        iflen(desc_containers) >= 2:            target_desc = desc_containers[1]            # print(target_desc)            # 使用正则表达式匹配软件包及其版本            pattern = re.compile(r'([a-zA-Z0-9\-]+)-([\d\.]+(?:-\d+)?(?:\.[a-zA-Z0-9]+)*(?:\.ky\d+))')            matches = pattern.findall(str(target_desc))            formatchin matches:                packages_list.append("{}-{}".format(match[0],match[1]))        unique_packages = set(packages_list)  # 类型变为set        return unique_packages            except Exception as e:        print(f"获取补丁信息失败: {str(e)}")        return '查询失败'
```  
### 生成更新软件包  
  
根据我们上面介绍的方法，您可以轻松获取到需要更新的软件包名称。接下来，我们将使用下面的函数把这些名称组合成一条完整的更新命令。具体步骤如下：  
```
# 生成yum更新命令（新增代码）def generate_yum_command(packages):    if not packages or packages in ('暂无修复包', '查询失败'):        return '# 无可用更新'    return f"yum update -y {' '.join(sorted(packages))}"
```  
### 重新组合数据  
  
为了将原始数据转换为我们需要的格式，我们可以利用Python  
中的强大工具——Pandas  
库来进行数据聚合处理。下面是具体的函数内容：  
```
def process_vulnerability_data(input_file, output_file):    """处理原始漏洞数据并生成修复计划表"""    # 读取数据    df = pd.read_excel(input_file, engine='openpyxl')        # 聚合处理    new_df = df.groupby('CVE号').agg({        '主机IP地址': lambda x: ', '.join(x),        '等级': 'first',        '漏洞描述': 'first',        '当前漏洞版本': 'first',        "官方修复方案": "first"    }).reset_index()        # 新增执行修复命令列    new_df['执行修复命令'] = new_df['官方修复方案'].apply(        lambda url: generate_yum_command(get_kylin_patches(url)) if pd.notnull(url) else'# 无修复链接'    )    # 计算主机数量    new_df['涉及主机数量'] = new_df['主机IP地址'].str.split(', ').apply(len)        # 调整列顺序    ordered_df = new_df[['CVE号', '主机IP地址', '涉及主机数量', '等级',                        '漏洞描述', '当前漏洞版本', '官方修复方案','执行修复命令']]        # 保存结果    ordered_df.to_excel(output_file, index=False)
```  
### 调用函数生成数据  
  
通过调用 process_vulnerability_data  
，输入两个参数：原始数据表以及输出表的名称。  
```
if __name__ == '__main__':    process_vulnerability_data(        input_file='漏洞表原始数据_test.xlsx',        output_file='漏洞修复计划表_test.xlsx'    )
```  
  
执行上述命令后，就可以得到我们想要的效果表。如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYs3ibJOqFcXy179icWZk246uUub1k8tzz7fh3bFdib7D9HaUFpmkqvjCTd2P5SnuZrlX2rJTtMzoicCxg/640?wx_fmt=png&from=appmsg "null")  
  
## 小结  
  
对于那些重复性的任务，我们可以考虑一下是否可以通过自动化工具或脚本来完成。这样做不仅能提高我们的工作效率，还能让我们有更多时间去休息或是专注于其他重要的事情上呢！  
## 推荐阅读  
- • [告别平淡无奇：用Markdown让你的公众号文章瞬间吸粉无数](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387388&idx=1&sn=c0d8f7bfbe34f5a76d76a455ecb5381d&scene=21#wechat_redirect)  
  
  
- • [别让通配符限制你的Ansible Fetch操作，这里有破解之道！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387338&idx=1&sn=0883d95f3564971ca7c3b6168d54ea33&scene=21#wechat_redirect)  
  
  
- • [如何用PAM模块加强Linux密码复杂度？一文搞定](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387328&idx=1&sn=ba2c7b56fe836057e3f3fe9ae9753c42&scene=21#wechat_redirect)  
  
  
- • [一步步教你用Python构建一个网络扫描工具，快速识别网络中的设备](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387298&idx=1&sn=6832f8a2564b7913b527b0c5ace290b1&scene=21#wechat_redirect)  
  
  
- • [如何在成百上千台服务器上轻松部署时间同步服务？只需这份Playbook！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387272&idx=1&sn=eb52863b1d2a5d27b57f9ffef4949d7b&scene=21#wechat_redirect)  
  
  
- • [如何用Ansible自动化收集和管理服务器日志？你需要这份Playbook！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387197&idx=1&sn=12f9523cd6d6d809266bdfdac22726f2&scene=21#wechat_redirect)  
  
  
  
  
   
  
  
