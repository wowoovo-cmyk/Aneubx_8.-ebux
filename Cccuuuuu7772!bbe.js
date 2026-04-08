function main(config) {
  // ========== 1. 基础设置 ==========
  config["mixed-port"] = 7897;
  config["allow-lan"] = true;
  config["mode"] = "rule";
  config["log-level"] = "info";
  config["unified-delay"] = true;
  config["tcp-concurrent"] = true;
  config["find-process-mode"] = "strict";
  config["geodata-mode"] = true;
  config["geo-auto-update"] = true;
  config["geodata-loader"] = "standard";
  config["geo-update-interval"] = 24;

  // ========== 2. Profile ==========
  config.profile = {
    "store-selected": true,
    "store-fake-ip": false,
  };

  // ========== 3. GeoX 数据源 ==========
  config["geox-url"] = {
    geoip:   "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    mmdb:    "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
    asn:     "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
  };

  // ========== 4. Sniffer ==========
  config.sniffer = {
    enable: true,
    "parse-pure-ip": true,
    sniff: {
      HTTP:  { ports: [80, "8080-8880"], "override-destination": true },
      TLS:   { ports: [443, 8443] },
      QUIC:  { ports: [443, 8443] },
    },
  };

  // ========== 5. DNS ==========
  config.dns = {
    enable: true,
    listen: "127.0.0.1:5335",
    "use-system-hosts": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "proxy-server-nameserver": [
      "223.5.5.5",
      "119.29.29.29",
      "https://dns.alidns.com/dns-query",
    ],
    nameserver: [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query",
      "223.5.5.5",
      "119.29.29.29",
    ],
    // 优化5：fallback 只保留 DoH，去掉明文 IP，避免国内污染
    fallback: [
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query",
    ],
    "fallback-filter": {
      geoip: true,
      "geoip-code": "CN",
      ipcidr: ["240.0.0.0/4", "0.0.0.0/32", "127.0.0.1/32"],
      domain: [
        "+.google.com", "+.facebook.com", "+.twitter.com", "+.youtube.com",
        "+.xn--ngstr-lra8j.com", "+.google.cn", "+.googleapis.cn",
        "+.googleapis.com", "+.gvt1.com", "+.telegram.org", "+.github.com",
        "+.openai.com", "+.anthropic.com",
      ],
    },
    "nameserver-policy": {
      "geosite:cn,private,geolocation-cn": [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
        "223.5.5.5",
        "119.29.29.29",
      ],
      "geosite:geolocation-!cn,google,youtube,telegram,openai,anthropic,github": [
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query",
      ],
    },
    "fake-ip-filter": [
      "*.lan", "stun.*.*.*", "stun.*.*", "time.windows.com", "time.nist.gov",
      "time.apple.com", "time.asia.apple.com", "*.ntp.org.cn", "*.openwrt.pool.ntp.org",
      "time1.cloud.tencent.com", "time.ustc.edu.cn", "pool.ntp.org", "ntp.ubuntu.com",
      "ntp.aliyun.com", "ntp1.aliyun.com", "ntp2.aliyun.com", "ntp3.aliyun.com",
      "ntp4.aliyun.com", "ntp5.aliyun.com", "ntp6.aliyun.com", "ntp7.aliyun.com",
      "time1.aliyun.com", "time2.aliyun.com", "time3.aliyun.com", "time4.aliyun.com",
      "time5.aliyun.com", "time6.aliyun.com", "time7.aliyun.com", "*.time.edu.cn",
      "time1.apple.com", "time2.apple.com", "time3.apple.com", "time4.apple.com",
      "time5.apple.com", "time6.apple.com", "time7.apple.com",
      "time1.google.com", "time2.google.com", "time3.google.com", "time4.google.com",
      "music.163.com", "*.music.163.com", "*.126.net", "musicapi.taihe.com",
      "music.taihe.com", "songsearch.kugou.com", "trackercdn.kugou.com", "*.kuwo.cn",
      "api-jooxtt.sanook.com", "api.joox.com", "joox.com", "y.qq.com", "*.y.qq.com",
      "streamoc.music.tc.qq.com", "mobileoc.music.tc.qq.com",
      "isure.stream.qqmusic.qq.com", "dl.stream.qqmusic.qq.com",
      "aqqmusic.tc.qq.com", "amobile.music.tc.qq.com", "*.xiami.com",
      "*.music.migu.cn", "music.migu.cn", "*.msftconnecttest.com", "*.msftncsi.com",
      "localhost.ptlogin2.qq.com", "*.*.*.srv.nintendo.net", "*.*.stun.playstation.net",
      "xbox.*.*.microsoft.com", "*.ipv6.microsoft.com", "*.*.xboxlive.com",
      "speedtest.cros.wr.pvp.net",
    ],
  };

  // ========== 6. 节点筛选 ==========
  const allProxies = (config.proxies || []).map((p) => p.name);
  const junkFilter = /免费|free|下载专用|剩余|流量|到期|expire|test|trial|体验|0\.0|x0\.|套餐|重置|公告|官网|频道/i;
  const cleanProxies = allProxies.filter((n) => !junkFilter.test(n));

  function filterNodes(regex) {
    return cleanProxies.filter((n) => regex.test(n));
  }

  const autoNodes  = cleanProxies;
  const hkNodes    = filterNodes(/港|hk|hongkong|hong.kong/i);
  const twNodes    = filterNodes(/台|tw|taiwan/i);
  const jpNodes    = filterNodes(/日|jp|japan/i);
  const sgNodes    = filterNodes(/新加坡|狮城|sg|singapore/i);
  const usNodes    = filterNodes(/美|us|unitedstates|united.states/i);
  const otherNodes = filterNodes(/韩|kr|korea|德|英|法|俄|土|印|加|澳|马|阿|fr|de|uk|gb|ru|tr|in|ca|au|my|ar/i);

  // 空数组保护
  const hkFinal    = hkNodes.length    > 0 ? hkNodes    : autoNodes;
  const twFinal    = twNodes.length    > 0 ? twNodes    : autoNodes;
  const jpFinal    = jpNodes.length    > 0 ? jpNodes    : autoNodes;
  const sgFinal    = sgNodes.length    > 0 ? sgNodes    : autoNodes;
  const usFinal    = usNodes.length    > 0 ? usNodes    : autoNodes;
  const otherFinal = otherNodes.length > 0 ? otherNodes : autoNodes;

  // ========== 7. 代理组 ==========
  config["proxy-groups"] = [
    { name: "手动选择", type: "select",   proxies: ["自动选择", "DIRECT", "REJECT", "香港", "台湾", "日本", "新加坡", "美国", "其他地区", ...autoNodes] },
    // 优化2：自动选择 interval 改为 600 秒，响应节点质量变化更及时
    { name: "自动选择", type: "url-test", proxies: autoNodes,  url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 150, lazy: true },
    { name: "香港",     type: "url-test", proxies: hkFinal,    url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 100, lazy: false },
    { name: "台湾",     type: "url-test", proxies: twFinal,    url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 100, lazy: false },
    { name: "日本",     type: "url-test", proxies: jpFinal,    url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 100, lazy: false },
    { name: "新加坡",   type: "url-test", proxies: sgFinal,    url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 100, lazy: false },
    { name: "美国",     type: "url-test", proxies: usFinal,    url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 100, lazy: false },
    // 优化1：其他地区改为 lazy:true，不常用时不持续后台测速
    { name: "其他地区", type: "url-test", proxies: otherFinal, url: "https://www.gstatic.com/generate_204", interval: 600, tolerance: 100, lazy: true },
    { name: "广告拦截", type: "select", proxies: ["REJECT", "DIRECT", "手动选择"] },
    { name: "人工智能", type: "select", proxies: ["手动选择", "自动选择", "台湾", "美国", "日本", "新加坡", "DIRECT", "REJECT"] },
    { name: "YouTube",  type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "DIRECT", "REJECT"] },
    { name: "谷歌服务", type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "DIRECT", "REJECT"] },
    { name: "微软服务", type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "其他地区", "DIRECT", "REJECT"] },
    { name: "苹果服务", type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "其他地区", "DIRECT", "REJECT"] },
    { name: "Telegram", type: "select", proxies: ["手动选择", "自动选择", "香港", "新加坡", "日本", "美国", "DIRECT", "REJECT"] },
    { name: "Netflix",  type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "REJECT"] },
    { name: "开发平台", type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "其他地区", "DIRECT", "REJECT"] },
    { name: "内网直连", type: "select", proxies: ["DIRECT", "REJECT", "手动选择"] },
    { name: "国内直连", type: "select", proxies: ["DIRECT", "REJECT", "手动选择"] },
    { name: "全球代理", type: "select", proxies: ["手动选择", "自动选择", "香港", "台湾", "日本", "新加坡", "美国", "其他地区", "DIRECT", "REJECT"] },
    { name: "最终规则", type: "select", proxies: ["手动选择", "自动选择", "DIRECT", "REJECT"] },
  ];

  // ========== 8. 规则集 ==========
  const CDN = "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo";
  config["rule-providers"] = {
    // 广告拦截（12小时更新）
    "anti-ad": {
      type: "http", behavior: "domain", format: "yaml", interval: 43200,
      path: "./ruleset/anti-ad.yaml",
      url: "https://fastly.jsdelivr.net/gh/privacy-protection-tools/anti-AD@master/anti-ad-clash.yaml",
    },
    "AWAvenue-Ads": {
      type: "http", behavior: "domain", format: "yaml", interval: 43200,
      path: "./ruleset/AWAvenue-Ads.yaml",
      url: "https://fastly.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Clash/AWAvenue-Ads-Rule-Clash.yaml",
    },
    "category-ads-all":     { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/category-ads-all.mrs",     url: `${CDN}/geosite/category-ads-all.mrs` },
    // 基础
    "115":                  { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/115.mrs",                  url: `${CDN}/geosite/115.mrs` },
    "private":              { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/private.mrs",              url: `${CDN}/geosite/private.mrs` },
    "private-ip":           { type: "http", behavior: "ipcidr",  format: "mrs", interval: 172800, path: "./ruleset/private-ip.mrs",           url: `${CDN}/geoip/private.mrs` },
    "geolocation-cn":       { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/geolocation-cn.mrs",       url: `${CDN}/geosite/geolocation-cn.mrs` },
    "cn-ip":                { type: "http", behavior: "ipcidr",  format: "mrs", interval: 172800, path: "./ruleset/cn-ip.mrs",                url: `${CDN}/geoip/cn.mrs` },
    "googlefcm":            { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/googlefcm.mrs",            url: `${CDN}/geosite/googlefcm.mrs` },
    "googlefcm@!cn":        { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/googlefcm@!cn.mrs",        url: `${CDN}/geosite/googlefcm@!cn.mrs` },
    "geolocation-!cn":      { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/geolocation-!cn.mrs",      url: `${CDN}/geosite/geolocation-!cn.mrs` },
    // AI
    "category-ai-chat-!cn": { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/category-ai-chat-!cn.mrs", url: `${CDN}/geosite/category-ai-chat-!cn.mrs` },
    "openai":               { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/openai.mrs",               url: `${CDN}/geosite/openai.mrs` },
    "anthropic":            { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/anthropic.mrs",            url: `${CDN}/geosite/anthropic.mrs` },
    "google-gemini":        { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/google-gemini.mrs",        url: `${CDN}/geosite/google-gemini.mrs` },
    "perplexity":           { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/perplexity.mrs",           url: `${CDN}/geosite/perplexity.mrs` },
    // 平台
    "youtube":              { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/youtube.mrs",              url: `${CDN}/geosite/youtube.mrs` },
    "google":               { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/google.mrs",               url: `${CDN}/geosite/google.mrs` },
    "google-ip":            { type: "http", behavior: "ipcidr",  format: "mrs", interval: 172800, path: "./ruleset/google-ip.mrs",            url: `${CDN}/geoip/google.mrs` },
    "microsoft":            { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/microsoft.mrs",            url: `${CDN}/geosite/microsoft.mrs` },
    "onedrive":             { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/onedrive.mrs",             url: `${CDN}/geosite/onedrive.mrs` },
    "apple":                { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/apple.mrs",                url: `${CDN}/geosite/apple.mrs` },
    "icloud":               { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/icloud.mrs",               url: `${CDN}/geosite/icloud.mrs` },
    "telegram":             { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/telegram.mrs",             url: `${CDN}/geosite/telegram.mrs` },
    "telegram-ip":          { type: "http", behavior: "ipcidr",  format: "mrs", interval: 172800, path: "./ruleset/telegram-ip.mrs",          url: `${CDN}/geoip/telegram.mrs` },
    "netflix":              { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/netflix.mrs",              url: `${CDN}/geosite/netflix.mrs` },
    "netflix-ip":           { type: "http", behavior: "ipcidr",  format: "mrs", interval: 172800, path: "./ruleset/netflix-ip.mrs",           url: `${CDN}/geoip/netflix.mrs` },
    "github":               { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/github.mrs",               url: `${CDN}/geosite/github.mrs` },
    "gitlab":               { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/gitlab.mrs",               url: `${CDN}/geosite/gitlab.mrs` },
    "atlassian":            { type: "http", behavior: "domain",  format: "mrs", interval: 172800, path: "./ruleset/atlassian.mrs",            url: `${CDN}/geosite/atlassian.mrs` },
    // 优化3：去掉 cn（geolocation-cn 已覆盖大部分，减少一次规则集加载）
    "cn-ip-final":          { type: "http", behavior: "ipcidr",  format: "mrs", interval: 172800, path: "./ruleset/cn-ip.mrs",                url: `${CDN}/geoip/cn.mrs` },
  };

  // ========== 9. 路由规则 ==========
  config.rules = [
    // 广告拦截（三层叠加：国内专项 + 秋风 + 通用）
    "RULE-SET,anti-ad,广告拦截",
    "RULE-SET,AWAvenue-Ads,广告拦截",
    "RULE-SET,category-ads-all,广告拦截",
    // AI 服务
    "RULE-SET,category-ai-chat-!cn,人工智能",
    "RULE-SET,openai,人工智能",
    "RULE-SET,anthropic,人工智能",
    "RULE-SET,google-gemini,人工智能",
    "RULE-SET,perplexity,人工智能",
    // 内网
    "RULE-SET,private,内网直连",
    "RULE-SET,private-ip,内网直连,no-resolve",
    // 自定义直连域名（parse-pure-ip:true 保证 fake-ip 模式下 DIRECT 正常工作）
    "DOMAIN,mtalk-dev.google.com,DIRECT",
    "DOMAIN,mtalk-staging.google.com,DIRECT",
    "DOMAIN,67982.eu.cc,DIRECT",
    "DOMAIN,emby.67982.eu.cc,DIRECT",
    "DOMAIN,auto.dolby.dpdns.org,DIRECT",
    "DOMAIN,emby.4348663.xyz,DIRECT",
    "DOMAIN,emby.sadchicktv.com,DIRECT",
    "DOMAIN,saodu6.cn,DIRECT",
    "DOMAIN,2.66990000.xyz,DIRECT",
    "DOMAIN,xxm.kingemby.xyz,DIRECT",
    "DOMAIN,emo1.525778.xyz,DIRECT",
    "DOMAIN-KEYWORD,miraiemby.com,DIRECT",
    "DOMAIN-KEYWORD,tyemby.klplay,DIRECT",
    "DOMAIN-KEYWORD,dayimakk.sharepoint,DIRECT",
    "DOMAIN-KEYWORD,mtalk.google,DIRECT",
    "DOMAIN-KEYWORD,theluyuan.com,DIRECT",
    "DOMAIN-KEYWORD,ey.626258,DIRECT",
    "DOMAIN-SUFFIX,embymv.link,DIRECT",
    "DOMAIN-SUFFIX,emby.my,DIRECT",
    "DOMAIN-SUFFIX,8880080.xyz,DIRECT",
    "DOMAIN-SUFFIX,api-huacloud.dev,DIRECT",
    // 流媒体 & 平台
    "RULE-SET,youtube,YouTube",
    "RULE-SET,google,谷歌服务",
    "RULE-SET,google-ip,谷歌服务,no-resolve",
    "RULE-SET,github,开发平台",
    "RULE-SET,gitlab,开发平台",
    "RULE-SET,atlassian,开发平台",
    "RULE-SET,microsoft,微软服务",
    "RULE-SET,onedrive,微软服务",
    "RULE-SET,apple,苹果服务",
    "RULE-SET,icloud,苹果服务",
    "RULE-SET,netflix,Netflix",
    "RULE-SET,netflix-ip,Netflix,no-resolve",
    // 自定义 IP 路由（ASN 归属地分流）
    "IP-ASN,44907,新加坡",
    "IP-ASN,62014,新加坡",
    "IP-ASN,59930,美国",
    "IP-ASN,62041,香港",
    "IP-ASN,211157,香港",
    "IP-CIDR,5.28.192.0/18,香港,no-resolve",
    "IP-CIDR,109.239.140.0/24,香港,no-resolve",
    // Telegram IP
    "IP-CIDR,149.154.175.0/22,Telegram,no-resolve",
    "IP-CIDR,149.154.167.0/22,Telegram,no-resolve",
    "IP-CIDR,149.154.168.0/22,Telegram,no-resolve",
    "IP-CIDR,149.154.172.0/22,Telegram,no-resolve",
    "IP-CIDR,91.108.56.0/22,Telegram,no-resolve",
    "IP-CIDR,91.108.4.0/22,Telegram,no-resolve",
    "IP-CIDR,91.108.8.0/22,Telegram,no-resolve",
    "IP-CIDR,91.108.12.0/22,Telegram,no-resolve",
    "IP-CIDR,91.108.16.0/22,Telegram,no-resolve",
    "IP-CIDR,91.105.192.0/23,Telegram,no-resolve",
    "IP-CIDR,185.76.151.0/24,Telegram,no-resolve",
    "IP-CIDR6,2001:b28:f23d::/48,Telegram,no-resolve",
    "IP-CIDR6,2001:b28:f23f::/48,Telegram,no-resolve",
    "IP-CIDR6,2001:67c:4e8::/48,Telegram,no-resolve",
    "IP-CIDR6,2001:b28:f22a::/48,Telegram,no-resolve",
    "RULE-SET,telegram,Telegram",
    "RULE-SET,telegram-ip,Telegram,no-resolve",
    // 国内
    "RULE-SET,geolocation-cn,国内直连",
    "RULE-SET,cn-ip,国内直连,no-resolve",
    "RULE-SET,googlefcm,国内直连",
    // 优化9：googlefcm@!cn 改为国内直连，FCM 推送走代理会影响 Android 消息到达率
    "RULE-SET,googlefcm@!cn,国内直连",
    "RULE-SET,115,国内直连",
    // 兜底
    "RULE-SET,geolocation-!cn,全球代理",
    "MATCH,最终规则",
  ];

  return config;
}
