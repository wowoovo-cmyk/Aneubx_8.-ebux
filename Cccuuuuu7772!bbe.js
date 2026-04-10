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
    
  config.profile = {    
    "store-selected": true,    
    "store-fake-ip": false,    
  };    
    
  config["geox-url"] = {    
    geoip: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",    
    geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",    
    mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",    
    asn: "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",    
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
    
  config.dns = {    
    enable: true,    
    listen: "0.0.0.0:5053",    
    ipv6: false,    
    "filter-aaaa": true,    
    "use-system-hosts": false,    
    "enhanced-mode": "fake-ip",    
    "fake-ip-range": "198.18.0.1/16",    
    "respect-rules": true,    
    "fake-ip-filter": [    
      "+.lan",    
      "+.local",    
      "+.msftconnecttest.com",    
      "+.msftncsi.com",    
      "localhost.ptlogin2.qq.com",    
      "time.*.com",    
      "stun.*.*",    
      "+.srv.nintendo.net",    
      "+.stun.playstation.net",    
      "+.xboxlive.com",    
      "music.163.com",    
      "+.music.163.com",    
      "+.126.net",    
      "+.kuwo.cn",    
      "+.y.qq.com",    
      "+.music.migu.cn",    
      "+.xiami.com"    
    ],    
    "proxy-server-nameserver": [    
      "https://doh.pub/dns-query"    
    ],    
    nameserver: [    
      "https://doh.pub/dns-query",    
      "https://dns.alidns.com/dns-query"    
    ],    
    fallback: [    
      "https://dns.google/dns-query",    
      "https://cloudflare-dns.com/dns-query"    
    ],    
    "nameserver-policy": {    
      "geosite:cn,private": [    
        "https://doh.pub/dns-query",    
        "https://dns.alidns.com/dns-query"    
      ],    
      "geosite:geolocation-!cn": [    
        "https://dns.google/dns-query",    
        "https://cloudflare-dns.com/dns-query"    
      ]    
    },    
    "fallback-filter": {    
      geoip: true,    
      "geoip-code": "CN",    
      ipcidr: ["240.0.0.0/4", "0.0.0.0/32", "127.0.0.1/32"],    
      domain: [    
        "+.google.com",    
        "+.facebook.com",    
        "+.twitter.com",    
        "+.youtube.com",    
        "+.xn--ngstr-lra8j.com",    
        "+.google.cn",    
        "+.googleapis.cn",    
        "+.googleapis.com",    
        "+.gvt1.com"    
      ]    
    }    
  };    
    
  const allProxies = (config.proxies || []).map((p) => p.name);    
  const junkFilter = /免费|free|下载专用|剩余|流量|到期|expire|test|trial|体验|0\.0|x0\.|套餐|重置|公告|官网|频道/i;    
  const cleanProxies = allProxies.filter((n) => !junkFilter.test(n));    
    
  function filterNodes(regex) {    
    return cleanProxies.filter((n) => regex.test(n));    
  }    
    
  const autoNodes = cleanProxies;    
  const hkNodes = filterNodes(/港|hk|hongkong|hong.kong/i);    
  const twNodes = filterNodes(/台|tw|taiwan/i);    
  const jpNodes = filterNodes(/日|jp|japan/i);    
  const sgNodes = filterNodes(/新加坡|狮城|sg|singapore/i);    
  const usNodes = filterNodes(/美|us|unitedstates|united.states/i);    
  const otherNodes = filterNodes(/韩|kr|korea|德|英|法|俄|土|印|加|澳|马|阿|fr|de|uk|gb|ru|tr|in|ca|au|my|ar/i);    
    
  const hkFinal = hkNodes.length > 0 ? hkNodes : autoNodes;    
  const twFinal = twNodes.length > 0 ? twNodes : autoNodes;    
  const jpFinal = jpNodes.length > 0 ? jpNodes : autoNodes;    
  const sgFinal = sgNodes.length > 0 ? sgNodes : autoNodes;    
  const usFinal = usNodes.length > 0 ? usNodes : autoNodes;    
  const otherFinal = otherNodes.length > 0 ? otherNodes : autoNodes;    
    
  const fullProxies = ["节点选择", "自动选择", "DIRECT", "REJECT", "香港", "台湾", "日本", "新加坡", "美国", "其他地区"];    
  const regionProxies = ["香港", "台湾", "日本", "新加坡", "美国", "其他地区"];    
    
  config["proxy-groups"] = [    
    { name: "节点选择", type: "select", proxies: ["自动选择", "DIRECT", "REJECT", ...regionProxies, ...autoNodes] },    
    { name: "自动选择", type: "url-test", proxies: autoNodes, url: "http://www.qualcomm.cn/generate_204", interval: 600, tolerance: 50, timeout: 5000, lazy: false },    
    { name: "AI 服务", type: "select", proxies: fullProxies },    
    { name: "油管视频", type: "select", proxies: fullProxies },    
    { name: "谷歌服务", type: "select", proxies: fullProxies },    
    { name: "微软服务", type: "select", proxies: fullProxies },    
    { name: "苹果服务", type: "select", proxies: fullProxies },    
    { name: "电报消息", type: "select", proxies: ["新加坡", "香港", "节点选择", "自动选择", "DIRECT", "REJECT", "美国", "日本", "台湾", "其他地区"] },    
    { name: "奈飞", type: "select", proxies: fullProxies },    
    { name: "代码托管", type: "select", proxies: fullProxies },    
    { name: "广告拦截", type: "select", proxies: ["REJECT", "DIRECT", "节点选择"] },    
    { name: "私有网络", type: "select", proxies: ["DIRECT", "REJECT", "节点选择", ...regionProxies] },    
    { name: "国内服务", type: "select", proxies: ["DIRECT", "REJECT", "节点选择", ...regionProxies] },    
    { name: "非中国", type: "select", proxies: fullProxies },    
    { name: "漏网之鱼", type: "select", proxies: fullProxies },    
    { name: "香港", type: "url-test", proxies: hkFinal, url: "http://www.qualcomm.cn/generate_204", interval: 300, tolerance: 50, timeout: 5000, lazy: false },    
    { name: "台湾", type: "url-test", proxies: twFinal, url: "http://www.qualcomm.cn/generate_204", interval: 300, tolerance: 50, timeout: 5000, lazy: false },    
    { name: "日本", type: "url-test", proxies: jpFinal, url: "http://www.qualcomm.cn/generate_204", interval: 300, tolerance: 50, timeout: 5000, lazy: false },    
    { name: "新加坡", type: "url-test", proxies: sgFinal, url: "http://www.qualcomm.cn/generate_204", interval: 300, tolerance: 50, timeout: 5000, lazy: false },    
    { name: "美国", type: "url-test", proxies: usFinal, url: "http://www.qualcomm.cn/generate_204", interval: 300, tolerance: 50, timeout: 5000, lazy: false },    
    { name: "其他地区", type: "url-test", proxies: otherFinal, url: "http://www.qualcomm.cn/generate_204", interval: 300, tolerance: 50, timeout: 5000, lazy: true },    
  ];    
    
  const GH = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo";    
  config["rule-providers"] = {    
    "anti-ad": { type: "http", behavior: "domain", format: "yaml", interval: 43200, path: "./ruleset/anti-ad.yaml", url: "https://testingcf.jsdelivr.net/gh/privacy-protection-tools/anti-AD@master/anti-ad-clash.yaml" },    
    "AWAvenue-Ads": { type: "http", behavior: "domain", format: "yaml", interval: 43200, path: "./ruleset/AWAvenue-Ads.yaml", url: "https://testingcf.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Clash.yaml" },    
    "category-ads-all": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/category-ads-all.mrs", url: `${GH}/geosite/category-ads-all.mrs` },    
    "private": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/private.mrs", url: `${GH}/geosite/private.mrs` },    
    "private-ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, path: "./ruleset/private-ip.mrs", url: `${GH}/geoip/private.mrs` },    
    "geolocation-cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/geolocation-cn.mrs", url: `${GH}/geosite/geolocation-cn.mrs` },    
    "cn-ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, path: "./ruleset/cn-ip.mrs", url: `${GH}/geoip/cn.mrs` },    
    "googlefcm": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/googlefcm.mrs", url: `${GH}/geosite/googlefcm.mrs` },    
    "googlefcm@!cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/googlefcm@!cn.mrs", url: `${GH}/geosite/googlefcm@!cn.mrs` },    
    "geolocation-!cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/geolocation-!cn.mrs", url: `${GH}/geosite/geolocation-!cn.mrs` },    
    "category-ai-chat-!cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/category-ai-chat-!cn.mrs", url: `${GH}/geosite/category-ai-chat-!cn.mrs` },    
    "openai": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/openai.mrs", url: `${GH}/geosite/openai.mrs` },    
    "anthropic": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/anthropic.mrs", url: `${GH}/geosite/anthropic.mrs` },    
    "google-gemini": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/google-gemini.mrs", url: `${GH}/geosite/google-gemini.mrs` },    
    "perplexity": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/perplexity.mrs", url: `${GH}/geosite/perplexity.mrs` },    
    "youtube": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/youtube.mrs", url: `${GH}/geosite/youtube.mrs` },    
    "google": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/google.mrs", url: `${GH}/geosite/google.mrs` },    
    "google-ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, path: "./ruleset/google-ip.mrs", url: `${GH}/geoip/google.mrs` },    
    "microsoft": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/microsoft.mrs", url: `${GH}/geosite/microsoft.mrs` },    
    "onedrive": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/onedrive.mrs", url: `${GH}/geosite/onedrive.mrs` },    
    "apple": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/apple.mrs", url: `${GH}/geosite/apple.mrs` },    
    "icloud": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/icloud.mrs", url: `${GH}/geosite/icloud.mrs` },    
    "telegram": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/telegram.mrs", url: `${GH}/geosite/telegram.mrs` },    
    "telegram-ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, path: "./ruleset/telegram-ip.mrs", url: `${GH}/geoip/telegram.mrs` },    
    "netflix": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/netflix.mrs", url: `${GH}/geosite/netflix.mrs` },    
    "netflix-ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, path: "./ruleset/netflix-ip.mrs", url: `${GH}/geoip/netflix.mrs` },    
    "github": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/github.mrs", url: `${GH}/geosite/github.mrs` },    
    "gitlab": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/gitlab.mrs", url: `${GH}/geosite/gitlab.mrs` },    
    "atlassian": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/atlassian.mrs", url: `${GH}/geosite/atlassian.mrs` },    
    "cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/cn.mrs", url: `${GH}/geosite/cn.mrs` },    
    "115": { type: "http", behavior: "domain", format: "mrs", interval: 86400, path: "./ruleset/115.mrs", url: `${GH}/geosite/115.mrs` },    
  };    
    
  config.rules = [    
    "RULE-SET,anti-ad,广告拦截",    
    "RULE-SET,AWAvenue-Ads,广告拦截",    
    "RULE-SET,category-ads-all,广告拦截",    
    "DOMAIN,mtalk-dev.google.com,国内服务",    
    "DOMAIN,mtalk-staging.google.com,国内服务",    
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
    "RULE-SET,category-ai-chat-!cn,AI 服务",    
    "RULE-SET,openai,AI 服务",    
    "RULE-SET,anthropic,AI 服务",    
    "RULE-SET,google-gemini,AI 服务",    
    "RULE-SET,perplexity,AI 服务",    
    "RULE-SET,youtube,油管视频",    
    "RULE-SET,google,谷歌服务",    
    "RULE-SET,google-ip,谷歌服务,no-resolve",    
    "RULE-SET,private,私有网络",    
    "RULE-SET,private-ip,私有网络,no-resolve",    
    "RULE-SET,geolocation-cn,国内服务",    
    "RULE-SET,cn-ip,国内服务,no-resolve",    
    "RULE-SET,googlefcm,国内服务",    
    "RULE-SET,googlefcm@!cn,国内服务",    
    "RULE-SET,115,国内服务",    
    "IP-ASN,44907,新加坡",    
    "IP-ASN,62014,新加坡",    
    "IP-ASN,59930,美国",    
    "IP-ASN,62041,香港",    
    "IP-ASN,211157,香港",    
    "IP-CIDR,5.28.192.0/18,香港,no-resolve",    
    "IP-CIDR,109.239.140.0/24,香港,no-resolve",    
    "IP-CIDR,149.154.175.0/22,电报消息,no-resolve",    
    "IP-CIDR,149.154.167.0/22,电报消息,no-resolve",    
    "IP-CIDR,149.154.168.0/22,电报消息,no-resolve",    
    "IP-CIDR,149.154.172.0/22,电报消息,no-resolve",    
    "IP-CIDR,91.108.56.0/22,电报消息,no-resolve",    
    "IP-CIDR,91.108.4.0/22,电报消息,no-resolve",    
    "IP-CIDR,91.108.8.0/22,电报消息,no-resolve",    
    "IP-CIDR,91.108.12.0/22,电报消息,no-resolve",    
    "IP-CIDR,91.108.16.0/22,电报消息,no-resolve",    
    "IP-CIDR,91.105.192.0/23,电报消息,no-resolve",    
    "IP-CIDR,185.76.151.0/24,电报消息,no-resolve",    
    "RULE-SET,telegram,电报消息",    
    "RULE-SET,telegram-ip,电报消息,no-resolve",    
    "RULE-SET,github,代码托管",    
    "RULE-SET,gitlab,代码托管",    
    "RULE-SET,atlassian,代码托管",    
    "RULE-SET,microsoft,微软服务",    
    "RULE-SET,onedrive,微软服务",    
    "RULE-SET,apple,苹果服务",    
    "RULE-SET,icloud,苹果服务",    
    "RULE-SET,netflix,奈飞",    
    "RULE-SET,netflix-ip,奈飞,no-resolve",    
    "RULE-SET,cn,国内服务",    
    "RULE-SET,geolocation-!cn,非中国",    
    "MATCH,漏网之鱼",    
  ];    
  return config;    
}
多维度的给这份配置文件打个分
