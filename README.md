# Free Node Collector

自动抓取公开免费代理节点，整合输出 V2Ray 订阅和 Clash 配置文件。

## 功能特性

- 自动从多个 GitHub 公开节点源抓取 V2Ray/Trojan/SS/SSR/Hysteria2 节点
- 自动抓取 Clash 订阅并合并生成统一配置
- 节点去重、过滤无效/局域网地址
- 输出格式：V2Ray Base64 订阅 + Clash YAML 配置
- 支持 GitHub Actions 定时自动运行（每天4次）
- 支持手动触发运行

## 输出文件

所有输出文件在 `2026免费节点/` 目录下：

| 文件 | 说明 | 使用方式 |
|------|------|---------|
| `2026免费节点/v2ray` | V2Ray Base64 订阅链接 | 导入 V2RayN/V2RayNG/Shadowrocket 等 |
| `2026免费节点/clash.yaml` | Clash 配置文件 | 导入 Clash/ClashX/ClashForAndroid 等 |
| `2026免费节点/nodes.txt` | 节点明细（可读） | 查看节点详情 |
| `2026免费节点/update_info.json` | 更新信息 | 查看最后更新时间和节点统计 |

## 使用方式

### 方式一：GitHub Actions 自动运行（推荐）

Fork 本仓库后，GitHub Actions 会自动每天运行 4 次（北京时间 8:00/14:00/20:00/2:00）。

也可以在仓库 Actions 页面手动点击 "Run workflow" 触发。

### 方式二：本地手动运行

```bash
# 安装依赖
pip install -r requirements.txt

# 运行抓取
python src/collector.py
```

输出文件在 `2026免费节点/` 目录下。

### 方式三：订阅链接（Fork 后可用）

Fork 本仓库并启用 Actions 后，可用以下链接订阅：

- V2Ray 订阅：`https://raw.githubusercontent.com/<你的用户名>/free-node-collector/main/2026免费节点/v2ray`
- Clash 订阅：`https://raw.githubusercontent.com/<你的用户名>/free-node-collector/main/2026免费节点/clash.yaml`

## 数据源

当前整合了以下公开免费节点源：

| 源 | 类型 | 说明 |
|----|------|------|
| freefq/free | base64 + clash | 每日更新 |
| Pawdroid/Free-servers | base64 + clash | 每日更新 |
| aiboboxx/v2rayfree | base64 + clash | 每日更新 |
| mahdibland/V2RayAggregator | base64 | 聚合多源 |
| yebekhe/TVC | base64 + clash | Telegram 频道收集 |
| barry-far/V2ray-Configs | base64 | 定期更新 |
| mfuu/v2ray | base64 + clash | 定期更新 |
| peasoft/NoMoreWalls | raw | 无墙节点列表 |

## 注意事项

- 本项目仅供学习交流使用，请遵守当地法律法规
- 免费节点不稳定，速度和可用性无法保证
- 建议用于临时需求，长期使用请购买正规服务
- 节点来源均为 GitHub 公开仓库，本项目不提供任何节点

## License

MIT
