function main(config) {
  config["ipv6"] = false;
  config["external-controller"] = "127.0.0.1:9090";
  config["secret"] = "";
  config["mixed-port"] = 7897;
  config["allow-lan"] = true;
  config["mode"] = "rule";
  config["log-level"] = "warning";
  config["unified-delay"] = true;
  config["tcp-concurrent"] = true;
  config["find-process-mode"] = "strict";
  config["geodata-mode"] = true;
  config["geo-auto-update"] = true;
  config["geodata-loader"] = "standard";
  config["geo-update-interval"] = 24;
  config["max-failed-times"] = 1;

  config.profile = {
    "store-selected": true,
    "store-fake-ip": false,
  };

  // 优化：全面剥离失效的 jsdelivr 镜像，替换为官方直连，并修正了错误的 ASN 数据库源
  config["geox-url"] = {
    geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
    geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb",
    asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
  };

  config["hosts"] = {
    "doh.pub": ["1.12.12.21", "1.12.12.12"],
    "dns.google": ["8.8.8.8", "8.8.4.4"],
    "dns.alidns.com": ["223.5.5.5", "223.6.6.6"],
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"]
  };

  config.sniffer = {
    enable: true,
    "parse-pure-ip": true,
    sniff: {
      HTTP: { ports: [80, "8080-8880"], "override-destination": true },
      QUIC: { ports: [443, 8443] },
      TLS: { ports: [443, 8443] },
    },
  };

  // 优化：DNS 内外联动防污染方案
  config.dns = {
    enable: true,
    listen: "0.0.0.0:5053",
    ipv6: false,
    "filter-aaaa": true,
    "use-system-hosts": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter-mode": "blacklist",
    "respect-rules": true,

    "fake-ip-filter": [
      "+.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com",
      "localhost.ptlogin2.qq.com", "time.*.com", "stun.*.*",
      "+.srv.nintendo.net", "+.stun.playstation.net", "+.xboxlive.com"
    ],

    "default-nameserver": ["223.5.5.5", "119.29.29.29"],

    "nameserver": [
      "https://doh.pub/dns-query",
      "https://dns.alidns.com/dns-query"
    ],

    "fallback": [
      "https://1.1.1.1/dns-query",
      "https://8.8.8.8/dns-query",
      "https://dns.google/dns-query"
    ],

    "fallback-filter": {
      "geoip": true,
      "geoip-code": "CN",
      "geosite": ["gfw"],
      "ipcidr": ["240.0.0.0/4"]
    },

    "nameserver-policy": {
      "geosite:private": "system",
      "geosite:cn": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
      "geosite:apple-cn": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
      "geosite:microsoft@cn": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
      "geosite:google-cn": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
      "geosite:geolocation-!cn": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
      "geosite:openai": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
      "geosite:anthropic": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
      "geosite:google-gemini": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
      "geosite:perplexity": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    },

    "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
    "direct-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
    "direct-nameserver-follow-policy": false
  };

  const allProxies = (config.proxies || []).map((p) => p.name);
  const junkFilter = /免费|free|下载专用|剩余|流量|到期|expire|test|trial|体验|0\.0|x0\.|套餐|重置|公告|官网|GB|频道/i;
  const cleanProxies = allProxies.filter((n) => !junkFilter.test(n));

  function filterNodes(regex) { return cleanProxies.filter((n) => regex.test(n)); }

  const autoNodes = cleanProxies;
  // 优化：严谨化正则表达式转义
  const hkNodes = filterNodes(/港|hk|hong\.kong/i);
  const twNodes = filterNodes(/台|tw|taiwan/i);
  const jpNodes = filterNodes(/日|jp|japan/i);
  const sgNodes = filterNodes(/新加坡|狮城|sg|singapore/i);
  const usNodes = filterNodes(/美|us|united\.states/i);
  const euNodes = filterNodes(/欧|eu|europe|欧洲|de|德国|fr|法国|nl|荷兰|it|意大利|es|西班牙|se|瑞典|ch|瑞士|英|uk|united kingdom|britain|gb/i);
  const otherNodes = filterNodes(/韩|kr|korea|俄|ru|russia|土|tr|turkey|印|in|india|加|ca|canada|澳|au|australia|马|my|malaysia|阿|ar|argentina|br|brazil|巴西/i);

  const hkFinal = hkNodes.length > 0 ? hkNodes : autoNodes;
  const twFinal = twNodes.length > 0 ? twNodes : autoNodes;
  const jpFinal = jpNodes.length > 0 ? jpNodes : autoNodes;
  const sgFinal = sgNodes.length > 0 ? sgNodes : autoNodes;
  const usFinal = usNodes.length > 0 ? usNodes : autoNodes;
  const euFinal = euNodes.length > 0 ? euNodes : autoNodes;
  const otherFinal = otherNodes.length > 0 ? otherNodes : autoNodes;

  const fullProxies = ["节点选择", "自动选择", "DIRECT", "REJECT", "香港", "台湾", "日本", "新加坡", "美国", "欧盟", "其他地区"];
  const regionProxies = ["香港", "台湾", "日本", "新加坡", "美国", "欧盟", "其他地区"];

  // 优化：更改为强 Anycast 的 HTTPS 测速地址，防止机场 HTTP 劫持伪造延迟
  const testUrl = "https://cp.cloudflare.com/generate_204"; 
  const testInterval = 300; 
  const testTolerance = 50; 
  const testTimeout = 3000; 

  config["proxy-groups"] = [
    { name: "节点选择", type: "select", proxies: ["自动选择", "DIRECT", "REJECT", ...regionProxies, ...autoNodes] },
    { name: "自动选择", type: "url-test", proxies: autoNodes, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "AI 服务", type: "select", proxies: fullProxies },
    { name: "谷歌服务", type: "select", proxies: fullProxies },
    { name: "电报消息", type: "select", proxies: ["节点选择", "新加坡", "香港", "自动选择", "DIRECT", "REJECT", "美国", "日本", "台湾", "欧盟", "其他地区"] },
    { name: "FCM 推送", type: "select", proxies: ["DIRECT", "节点选择", "香港", "台湾", "日本", "新加坡", "美国", "自动选择", "REJECT"] },
    { name: "流媒体", type: "select", proxies: fullProxies },
    { name: "油管视频", type: "select", proxies: fullProxies },
    { name: "奈飞", type: "select", proxies: fullProxies },
    { name: "TikTok", type: "select", proxies: ["台湾", "日本", "新加坡", "美国", "节点选择", "自动选择"] },
    { name: "社交平台", type: "select", proxies: fullProxies },
    { name: "微软服务", type: "select", proxies: fullProxies },
    { name: "苹果服务", type: "select", proxies: fullProxies },
    { name: "代码托管", type: "select", proxies: fullProxies },
    { name: "游戏平台", type: "select", proxies: ["DIRECT", "节点选择", "香港", "日本", "台湾"] },
    { name: "广告拦截", type: "select", proxies: ["REJECT", "DIRECT", "节点选择"] },
    { name: "私有网络", type: "select", proxies: ["DIRECT", "REJECT", "节点选择", ...regionProxies] },
    { name: "国内服务", type: "select", proxies: ["DIRECT", "REJECT", "节点选择", ...regionProxies] },
    { name: "国内网盘", type: "select", proxies: ["DIRECT", "国内服务", "节点选择"] },
    { name: "非中国", type: "select", proxies: fullProxies },
    { name: "漏网之鱼", type: "select", proxies: fullProxies },
    { name: "香港", type: "url-test", proxies: hkFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "台湾", type: "url-test", proxies: twFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "日本", type: "url-test", proxies: jpFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "新加坡", type: "url-test", proxies: sgFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "美国", type: "url-test", proxies: usFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "欧盟", type: "url-test", proxies: euFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
    { name: "其他地区", type: "url-test", proxies: otherFinal, url: testUrl, interval: testInterval, tolerance: testTolerance, timeout: testTimeout, lazy: true },
  ];

  // 优化：彻底剥离 testingcf.jsdelivr.net 镜像，使用 raw.githubusercontent.com 直连
  var GH = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo";
  config["rule-providers"] = {
    "Anti-AD": { type: "http", behavior: "domain", format: "yaml", interval: 86400, path: "./ruleset/anti_ad.yaml", url: "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml" },
    "AWAvenue-Ads": { type: "http", behavior: "domain", format: "yaml", interval: 604800, path: "./ruleset/AWAvenue-Ads.yaml", url: "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.yaml" },
    "gfw": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/gfw.mrs", url: GH + "/geosite/gfw.mrs" },
    "tld-not-cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/tld-not-cn.mrs", url: GH + "/geosite/tld-!cn.mrs" },
    "cncidr": { type: "http", behavior: "ipcidr", format: "mrs", interval: 604800, path: "./ruleset/cncidr.mrs", url: GH + "/geoip/cn.mrs" },
    "private-ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 604800, path: "./ruleset/private-ip.mrs", url: GH + "/geoip/private.mrs" },
    "geolocation-cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/geolocation-cn.mrs", url: GH + "/geosite/geolocation-cn.mrs" },
    "googlefcm": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/googlefcm.mrs", url: GH + "/geosite/googlefcm.mrs" },
    "googlefcm@!cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/googlefcm@!cn.mrs", url: GH + "/geosite/googlefcm@!cn.mrs" },
    "category-ai-chat-!cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/category-ai-chat-!cn.mrs", url: GH + "/geosite/category-ai-chat-!cn.mrs" },
    "openai": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/openai.mrs", url: GH + "/geosite/openai.mrs" },
    "anthropic": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/anthropic.mrs", url: GH + "/geosite/anthropic.mrs" },
    "google-gemini": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/google-gemini.mrs", url: GH + "/geosite/google-gemini.mrs" },
    "perplexity": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/perplexity.mrs", url: GH + "/geosite/perplexity.mrs" },
    "OverseasAI": { type: "http", behavior: "classical", format: "text", interval: 604800, path: "./ruleset/OverseasAI.list", url: "https://raw.githubusercontent.com/viewer12/OverseasAI.list/main/rule/Clash/OverseasAI/OverseasAI.list" },
    "youtube": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/youtube.mrs", url: GH + "/geosite/youtube.mrs" },
    "netflix": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/netflix.mrs", url: GH + "/geosite/netflix.mrs" },
    "tiktok": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/tiktok.mrs", url: GH + "/geosite/tiktok.mrs" },
    "spotify": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/spotify.mrs", url: GH + "/geosite/spotify.mrs" },
    "disney": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/disney.mrs", url: GH + "/geosite/disney.mrs" },
    "primevideo": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/primevideo.mrs", url: GH + "/geosite/primevideo.mrs" },
    "telegram": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/telegram.mrs", url: GH + "/geosite/telegram.mrs" },
    "twitter": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/twitter.mrs", url: GH + "/geosite/twitter.mrs" },
    "facebook": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/facebook.mrs", url: GH + "/geosite/facebook.mrs" },
    "instagram": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/instagram.mrs", url: GH + "/geosite/instagram.mrs" },
    "discord": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/discord.mrs", url: GH + "/geosite/discord.mrs" },
    "google": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/google.mrs", url: GH + "/geosite/google.mrs" },
    "microsoft": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/microsoft.mrs", url: GH + "/geosite/microsoft.mrs" },
    "onedrive": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/onedrive.mrs", url: GH + "/geosite/onedrive.mrs" },
    "apple": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/apple.mrs", url: GH + "/geosite/apple.mrs" },
    "icloud": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/icloud.mrs", url: GH + "/geosite/icloud.mrs" },
    "github": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/github.mrs", url: GH + "/geosite/github.mrs" },
    "gitlab": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/gitlab.mrs", url: GH + "/geosite/gitlab.mrs" },
    "atlassian": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/atlassian.mrs", url: GH + "/geosite/atlassian.mrs" },
    "steam": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/steam.mrs", url: GH + "/geosite/steam.mrs" },
    "epicgames": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/epicgames.mrs", url: GH + "/geosite/epicgames.mrs" },
    "aliyun-drive": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/aliyun-drive.mrs", url: GH + "/geosite/aliyun.mrs" },
    "115": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/115.mrs", url: GH + "/geosite/115.mrs" },
    "bilibili": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/bilibili.mrs", url: GH + "/geosite/bilibili.mrs" },
    "apple-cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/apple-cn.mrs", url: GH + "/geosite/apple-cn.mrs" },
    "microsoft-cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/microsoft-cn.mrs", url: GH + "/geosite/microsoft@cn.mrs" },
    "steam-cn": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/steam-cn.mrs", url: GH + "/geosite/steam@cn.mrs" },
    "netease": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/netease.mrs", url: GH + "/geosite/netease.mrs" },
    "alibaba": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/alibaba.mrs", url: GH + "/geosite/alibaba.mrs" },
    "jd": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/jd.mrs", url: GH + "/geosite/jd.mrs" },
    "xiaohongshu": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/xiaohongshu.mrs", url: GH + "/geosite/xiaohongshu.mrs" },
    "xunlei": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/xunlei.mrs", url: GH + "/geosite/xunlei.mrs" },
    "tencent": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/tencent.mrs", url: GH + "/geosite/tencent.mrs" },
    "baidu": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/baidu.mrs", url: GH + "/geosite/baidu.mrs" },
    "iqiyi": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/iqiyi.mrs", url: GH + "/geosite/iqiyi.mrs" },
    "kuaishou": { type: "http", behavior: "domain", format: "mrs", interval: 604800, path: "./ruleset/kuaishou.mrs", url: GH + "/geosite/kuaishou.mrs" }
  };
  
  config.rules = [
    "RULE-SET,private-ip,私有网络,no-resolve",
    "DST-PORT,6881-6889,DIRECT",
    "DOMAIN-KEYWORD,tracker,DIRECT",
    "DOMAIN-KEYWORD,announce,DIRECT",
    "DOMAIN-KEYWORD,torrent,DIRECT",
    "DOMAIN-SUFFIX,speedtest.net,DIRECT",
    "DOMAIN-SUFFIX,ooklaserver.net,DIRECT",
    "DOMAIN-KEYWORD,baidupcs,DIRECT",
    "DOMAIN-KEYWORD,quark,DIRECT",
    "RULE-SET,Anti-AD,广告拦截",
    "RULE-SET,AWAvenue-Ads,广告拦截",
    "RULE-SET,OverseasAI,AI 服务",
    "DOMAIN,67982.eu.cc,国内服务",
    "DOMAIN,emby.67982.eu.cc,国内服务",
    "DOMAIN,auto.dolby.dpdns.org,国内服务",
    "DOMAIN,emby.4348663.xyz,国内服务",
    "DOMAIN,emby.sadchicktv.com,国内服务",
    "DOMAIN,saodu6.cn,国内服务",
    "DOMAIN,2.66990000.xyz,国内服务",
    "DOMAIN,xxm.kingemby.xyz,国内服务",
    "DOMAIN,emo1.525778.xyz,国内服务",
    "DOMAIN-KEYWORD,miraiemby.com,国内服务",
    "DOMAIN-KEYWORD,tyemby.klplay,国内服务",
    "DOMAIN-KEYWORD,dayimakk.sharepoint,国内服务",
    "DOMAIN-KEYWORD,mtalk.google,国内服务",
    "DOMAIN-KEYWORD,theluyuan.com,国内服务",
    "DOMAIN-KEYWORD,ey.626258,国内服务",
    "DOMAIN-SUFFIX,embymv.link,国内服务",
    "DOMAIN-SUFFIX,emby.my,国内服务",
    "DOMAIN-SUFFIX,8880080.xyz,国内服务",
    "DOMAIN-SUFFIX,api-huacloud.dev,国内服务",
    "RULE-SET,aliyun-drive,国内网盘",
    "RULE-SET,115,国内网盘",
    "RULE-SET,bilibili,DIRECT",
    "RULE-SET,apple-cn,DIRECT",
    "RULE-SET,microsoft-cn,DIRECT",
    "RULE-SET,steam-cn,DIRECT",
    "RULE-SET,netease,DIRECT",
    "RULE-SET,alibaba,DIRECT",
    "RULE-SET,jd,DIRECT",
    "RULE-SET,xiaohongshu,DIRECT",
    "RULE-SET,xunlei,DIRECT",
    "RULE-SET,tencent,DIRECT",
    "RULE-SET,baidu,DIRECT",
    "RULE-SET,iqiyi,DIRECT",
    "RULE-SET,kuaishou,DIRECT",
    "RULE-SET,googlefcm,FCM 推送",
    "RULE-SET,googlefcm@!cn,FCM 推送",
    "RULE-SET,category-ai-chat-!cn,AI 服务",
    "RULE-SET,openai,AI 服务",
    "RULE-SET,anthropic,AI 服务",
    "RULE-SET,google-gemini,AI 服务",
    "RULE-SET,perplexity,AI 服务",
    "RULE-SET,youtube,油管视频",
    "RULE-SET,netflix,奈飞",
    "RULE-SET,tiktok,TikTok",
    "RULE-SET,spotify,流媒体",
    "RULE-SET,disney,流媒体",
    "RULE-SET,primevideo,流媒体",
    "IP-CIDR,91.108.16.0/21,新加坡,no-resolve",
    "IP-CIDR,91.108.56.0/23,新加坡,no-resolve",
    "IP-CIDR,149.154.168.0/22,新加坡,no-resolve",
    "IP-CIDR6,2001:b28:f23c::/48,新加坡,no-resolve",
    "IP-CIDR6,2001:b28:f23f::/48,新加坡,no-resolve",
    "IP-CIDR,91.108.12.0/22,美国,no-resolve",
    "IP-CIDR,149.154.172.0/22,美国,no-resolve",
    "IP-CIDR6,2001:b28:f23d::/48,美国,no-resolve",
    "IP-CIDR,5.28.192.0/18,欧盟,no-resolve",
    "IP-CIDR,91.105.192.0/23,欧盟,no-resolve",
    "IP-CIDR,91.108.4.0/22,欧盟,no-resolve",
    "IP-CIDR,91.108.8.0/22,欧盟,no-resolve",
    "IP-CIDR,91.108.56.0/22,欧盟,no-resolve",
    "IP-CIDR,95.161.64.0/20,欧盟,no-resolve",
    "IP-CIDR,109.239.140.0/24,欧盟,no-resolve",
    "IP-CIDR,149.154.160.0/21,欧盟,no-resolve",
    "IP-CIDR,185.76.151.0/24,欧盟,no-resolve",
    "IP-CIDR6,2001:67c:4e8::/48,欧盟,no-resolve",
    "IP-CIDR6,2a0a:f280:203::/48,欧盟,no-resolve",
    "RULE-SET,telegram,电报消息",
    "RULE-SET,twitter,社交平台",
    "RULE-SET,facebook,社交平台",
    "RULE-SET,instagram,社交平台",
    "RULE-SET,discord,社交平台",
    "RULE-SET,github,代码托管",
    "RULE-SET,gitlab,代码托管",
    "RULE-SET,atlassian,代码托管",
    "RULE-SET,microsoft,微软服务",
    "RULE-SET,onedrive,微软服务",
    "RULE-SET,apple,苹果服务",
    "RULE-SET,icloud,苹果服务",
    "RULE-SET,google,谷歌服务",
    "RULE-SET,steam,游戏平台",
    "RULE-SET,epicgames,游戏平台",
    "RULE-SET,gfw,节点选择",
    "IP-ASN,44907,新加坡,no-resolve",
    "IP-ASN,62014,新加坡,no-resolve",
    "IP-ASN,59930,美国,no-resolve",
    "IP-ASN,62041,欧盟,no-resolve",
    "IP-ASN,211157,欧盟,no-resolve",
    "RULE-SET,geolocation-cn,DIRECT",
    "DOMAIN-SUFFIX,cn,DIRECT",
    "RULE-SET,tld-not-cn,非中国",
    "RULE-SET,cncidr,DIRECT",
    "MATCH,漏网之鱼"
  ];

  return config;
}
