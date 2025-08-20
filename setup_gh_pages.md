# 启用GitHub Pages指南

按照以下步骤在你的GitHub仓库中启用GitHub Pages功能，以展示daily.html安全报告页面。

## 步骤1: 确保gh-pages分支存在

1. 查看是否已创建gh-pages分支:
   ```bash
   git branch -a
   ```
2. 如果没有看到`gh-pages`分支，请等待工作流自动创建，或手动创建:
   ```bash
   git checkout --orphan gh-pages
   git rm -rf .
   touch README.md
   git add README.md
   git commit -m "Initial gh-pages commit"
   git push origin gh-pages
   ```

## 步骤2: 启用GitHub Pages

1. 访问你的GitHub仓库页面
2. 点击顶部导航栏中的 **Settings** 选项卡
3. 在左侧边栏中找到并点击 **Pages** 选项
4. 在 **Build and deployment** 部分:
   - 选择 **Deploy from a branch** 作为Source
   - 从Branch下拉菜单中选择 **gh-pages** 分支
   - 选择 **/(root)** 作为文件夹
5. 点击 **Save** 按钮

## 步骤3: 等待部署完成

- GitHub Pages会自动部署你的网站
- 部署完成后，你会在Pages设置页面看到一个绿色的成功消息和你的网站URL
- 通常URL格式为: `https://<username>.github.io/<repository-name>/`

## 步骤4: 验证访问

1. 打开浏览器，访问提供的GitHub Pages URL
2. 你应该能看到最新的安全威胁态势报告页面

## 自动更新机制

- 配置完成后，每当`update_daily.yml`工作流成功执行，`deploy_gh_pages.yml`工作流会自动触发
- 新的安全报告将自动部署到GitHub Pages，通常在几分钟内完成更新

## 故障排除

如果遇到问题:

1. 确保gh-pages分支存在并且包含index.html文件
2. 检查GitHub Actions工作流的执行状态
3. 确认仓库设置中的Pages配置正确
4. 清除浏览器缓存后重试访问

如果问题仍然存在，请查看GitHub Pages的官方文档或联系仓库管理员。