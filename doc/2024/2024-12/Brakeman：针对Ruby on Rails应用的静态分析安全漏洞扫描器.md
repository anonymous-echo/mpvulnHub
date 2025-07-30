#  Brakeman：针对Ruby on Rails应用的静态分析安全漏洞扫描器   
Alpha_h4ck  FreeBuf   2024-12-30 11:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于Brakeman**  
  
  
## Brakeman是一款功能强大的静态安全分析工具，该工具旨在针对Ruby on Rails应用程序执行静态分析与安全漏洞扫描任务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibFlAHdVuL2Z0XPIPN8aVSgcCCx0NkAQ3zs1Aicia2Og4Jxnt5XeVTv6hljNbBHCicbNMgAPJWb9mmtQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
##   
  
**工具要求**  
  
  
##   
> gem  
  
##   
  
**工具安装**  
  
  
  
##   
  
使用 RubyGems：  
```
gem install brakeman
```  
  
  
使用Bundler：  
```
group :development do

  gem 'brakeman', require: false

end
```  
  
  
使用Docker：  
```
docker pull presidentbeef/brakeman
```  
  
使用 Docker 从源代码构建：  
```
```  
```
git clone https://github.com/presidentbeef/brakeman.git

cd brakeman

docker build . -t brakeman

```  
```
```  
  
**工具使用**  
  
  
### 本地运行  
  
  
从 Rails 应用程序的根目录运行：  
```
brakeman
```  
  
  
从 Rails 根目录之外的地方运行：  
```
brakeman /path/to/rails/application
```  
###   
### 使用 Docker 运行  
  
  
从 Rails 应用程序的根目录运行：  
```
docker run -v "$(pwd)":/code presidentbeef/brakeman
```  
  
  
开启颜色高亮显示：  
```
docker run -v "$(pwd)":/code presidentbeef/brakeman --color
```  
  
  
显示并输出 HTML 报告：  
```
docker run -v "$(pwd)":/code presidentbeef/brakeman -o brakeman_results.html
```  
```
```  
  
在 Rails 根目录之外运行（请注意，输出文件与 path/to/rails/application 相关）：  
```
docker run -v 'path/to/rails/application':/code presidentbeef/brakeman -o brakeman_results.html
```  
```
```  
  
**工具配置**  
  
  
##   
  
该工具的阐述选项可以存储并从 YAML 文件中读取，为了简化编写配置文件的过程，-C选项将输出当前设置的选项：  
```
$ brakeman -C --skip-files plugins/

---

:skip_files:

- plugins/

```  
```
```  
  
默认配置位置为./config/brakeman.yml、~/.brakeman/config.yml和/etc/brakeman/config.yml。  
  
  
需要注意的是，命令行中传递的选项优先于配置文件。  
##   
  
**工具使用样例**  
  
  
## 使用 Brakeman 的最简单方法是在 Rails 应用程序的根目录中直接运行它，无需任何选项：  
```
cd your_rails_app/

brakeman
```  
  
  
这将扫描当前目录中的应用程序并将报告输出到命令行。  
  
  
或者，你可以向 Brakeman 提供一个路径作为选项：  
```
brakeman your_rails_app
```  
  
  
比如说：  
```
brakeman -p your_rails_app
```  
##   
  
**许可证协议**  
  
  
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**Brakeman**：  
  
  
https://github.com/presidentbeef/brakeman  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
