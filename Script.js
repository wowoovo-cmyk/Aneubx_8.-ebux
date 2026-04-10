const { url, name } = $arguments;

// 1. 读取模板配置
let config = JSON.parse($files[0]);

// 2. 获取订阅原始文本
let raw;
if (url) {
  // 直接通过 URL 拉取（支持远程订阅地址）
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);
  try {
    const resp = await fetch(url, { signal: controller.signal });
    raw = await resp.text();
  } catch (e) {
    throw new Error(`订阅拉取失败: ${e.message}`);
  } finally {
    clearTimeout(timeoutId);
  }
} else if (name) {
  // 通过内部 artifact 名称拉取（备用）
  const artifact = await produceArtifact({
    name,
    type: "subscription",
    platform: "sing-box",
    produceType: "internal",
  });
  // produceArtifact 返回的已经是解析后的数组，直接赋值跳过解析
  let proxies = artifact;
  // 跳过后续解析步骤，直接进入过滤和注入
} else {
  throw new Error("必须提供 url 或 name 参数");
}

// 3. 如果通过 URL 获取了 raw，则解析为节点数组
let proxies;
if (raw) {
  try {
    proxies = $substore.parseSubscription(raw, { platform: "sing-box" });
  } catch (e) {
    throw new Error(`订阅解析失败: ${e.message}\n原始内容前200字符: ${raw.slice(0, 200)}`);
  }
}

// 4. 节点过滤
const excludeKeywords = ["免费", "free", "下载", "剩余", "流量", "到期", "expire", "test", "trial", "体验", "0.0", "套餐", "重置", "公告", "官网", "频道"];
proxies = proxies.filter(p => {
  const lowerName = p.tag.toLowerCase();
  return !excludeKeywords.some(kw => lowerName.includes(kw.toLowerCase()));
});

// 5. 去重并追加到 outbounds
const existingTags = new Set(config.outbounds.map(o => o.tag));
proxies = proxies.filter(p => !existingTags.has(p.tag));
config.outbounds.push(...proxies);

// 6. 地区分组关键词
const regionGroups = [
  { tag: "香港", keywords: ["港", "hk", "hongkong", "hong kong"] },
  { tag: "台湾", keywords: ["台", "tw", "taiwan"] },
  { tag: "日本", keywords: ["日", "jp", "japan"] },
  { tag: "新加坡", keywords: ["新加坡", "狮城", "sg", "singapore"] },
  { tag: "美国", keywords: ["美", "us", "unitedstates", "united states"] },
  { tag: "其他地区", keywords: ["韩", "kr", "korea", "德", "英", "法", "俄", "土", "印", "加", "澳", "马", "阿", "fr", "de", "uk", "gb", "ru", "tr", "in", "ca", "au", "my", "ar"] }
];

// 7. 注入 urltest 组
config.outbounds.forEach(group => {
  if (group.type !== "urltest" || !Array.isArray(group.outbounds)) return;
  const region = regionGroups.find(r => r.tag === group.tag);
  if (region) {
    const matchedTags = proxies.filter(p => region.keywords.some(kw => p.tag.toLowerCase().includes(kw.toLowerCase()))).map(p => p.tag);
    group.outbounds.push(...matchedTags);
  } else if (group.tag === "自动选择") {
    group.outbounds.push(...proxies.map(p => p.tag));
  }
});

// 8. 注入 selector 组
config.outbounds.forEach(group => {
  if (group.type === "selector" && Array.isArray(group.outbounds) && group.tag !== "direct") {
    group.outbounds.push(...proxies.map(p => p.tag));
  }
});

// 9. 全局去重
config.outbounds.forEach(g => {
  if (Array.isArray(g.outbounds)) g.outbounds = [...new Set(g.outbounds)];
});

// 10. 输出最终配置
$content = JSON.stringify(config, null, 2);
