#  最新Nacos 漏洞复现与修复建议   
 攻防训练营   2024-07-15 21:05  
  
# 环境搭建  
  
首先拉取Nacos的docker镜像  
```
git clone https://github.com/nacos-group/nacos-docker.git
cd nacos-docker
```  
  
这里改一下  
example/standalone-derby.yaml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4mwXmdMZYPtYeFia3FmBrVrqWGRB9YIWxy1z4wOtPlbkCSOE6WJe93Vl4Bc5pdwC3ckUVOX9DKMI5g/640?wx_fmt=png&from=appmsg "")  
```
docker-compose -f example/standalone-derby.yaml up
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4mwXmdMZYPtYeFia3FmBrVrqHuYoL0KIzJVooh8YD4zOibfhJBg0PWoWavfMibMurXicpdIh9XWOb2GaA/640?wx_fmt=png&from=appmsg "")  
# 漏洞复现  
  
编辑config.py文件![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4mwXmdMZYPtYeFia3FmBrVrqr8EibO20N3ChacWOq6msG7rdibA3JjlO2pA4H3PIdrnQYaTnQcQHuBUA/640?wx_fmt=png&from=appmsg "")  
  
  
这里我把exploit.py里面地址改成了我自己的IP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4mwXmdMZYPtYeFia3FmBrVrqjkakFtHNiccCgLlXXAiaEibF3ltvLG3icjtkDdRNKNicq5fgGj74gr1Xzkw/640?wx_fmt=png&from=appmsg "")  
  
然后运行server.py  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4mwXmdMZYPtYeFia3FmBrVrqhVvib2U8EibswtIVECDxKSkTNQyDmZicCfKtwe8O0rv2h1b80oMPsVFPA/640?wx_fmt=png&from=appmsg "")  
运行exp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4mwXmdMZYPtYeFia3FmBrVrqSqAfQeKa9dBwFm00m3queEKhInxLGTS3eCe0hzFkWDjq7tlfJTHBVA/640?wx_fmt=png&from=appmsg "")  
# 修复建议  
1. **升级nacos到最新版本（虽然无法修复漏洞，但是可以避免之前的未授权漏洞）**  
。  
  
1. **禁止nacos的匿名访问，开启鉴权**  
。  
  
1. **nacos设置复杂的密码**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HKQyIxgrd4m0Wl7JVxjwvFwWVaNboDZkzZhgLm0EGxroN3AaunfOkib4QS9vRG5kgrK0HItk6Ofz1ibk0fWiclySQ/640?wx_fmt=gif "")  
  
  
欢迎进入内部星球一起交流  
  
                                              
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HKQyIxgrd4nzXyJkbhkf9NGBjfAvlribdiahGM4SbuLjeSibk5s8aGcjxFk7FCEnVRItPNLic9HpkOvYSocSabp6mw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
攻防训练营  
  
攻防训练营是高质量的网络安全领域星球，星球中有针对安全新人的优秀入门学习资料、  
各类攻防、CTF信息、攻防工具、技巧、书籍等各种资源，  
所有发布的内容均精心挑选、成体系化，让你远离无用信息及零碎的知识点。  
致力以手把手的模式引导广大网络安全从业者转型为安全技术人员，欢迎您的加入！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4kOxMk08lxmtrCMvgwyaOww6yv6cfiaM0sb1Key5K8fdU3H9DNooNtU7fNkHLVU8iaoav1CXEich26Ag/640?wx_fmt=png "")  
  
awd攻防神器  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HKQyIxgrd4kOxMk08lxmtrCMvgwyaOwwbdicMpKmPpuWt5ctI6z6Sficr1T8Y1eLiahBwO8vZzYsUN7tLibLs4ytkw/640?wx_fmt=jpeg "")  
  
  
专属靶场  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HKQyIxgrd4kOxMk08lxmtrCMvgwyaOwwneSricZnFAgwQCZUrzPuiavABf7ynhox3iaBadNX9zS3UaiccXgdjnsWxw/640?wx_fmt=jpeg "")  
  
有专门的视频指导您从0到1学习  
  
b站r00t_1  
  
https://space.bilibili.com/317711147  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HKQyIxgrd4kOxMk08lxmtrCMvgwyaOwwNic9LBnMich46NjCwFQeWnARaM0JJKZQv9k6VnmnaIeU5O3X99zybo4Q/640?wx_fmt=png "")  
  
加入攻防训练营星球你能得到什么？  
  
1. awd攻防神器（一键获取提交flag、一键植入蠕虫不死马、快速扫描工具等等）以及源码（还在更新工具中）
2. 专题更新漏洞挖掘小技巧，仿真实战靶场wp
3. 遇到任何技术问题都可以提问与交流
4. 内部专属培训课程（网络攻防，漏洞挖掘、代码审计）
5. 获得最新漏洞信息与攻防工具
6. 近距离与安全大咖接触交流与大厂面试心得
7. 漏洞poc编写技巧（goby、X-ray、nuclei）
8. 良好的团队氛围，不定期举办攻防比赛  
  
  
  
