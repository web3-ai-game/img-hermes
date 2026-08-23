# 🌌 Hermes Control Hub (img-hermes)

[![Hermes Version](https://img.shields.io/badge/Hermes_Agent-v0.19.0-blue.svg)](https://github.com/web3-ai-game/img-hermes)
[![Node Version](https://img.shields.io/badge/Node.js-v22.x_LTS-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Security Gate](https://img.shields.io/badge/Security-PIN_Gated-gold.svg)](#-security--pin-gate)

**Hermes Control Hub** (`img-hermes`) 是專為 **Hermes Autonomous Agent** 量身打造的次世代全功能旗艦儀表板與視覺化指揮中樞。集成了即時 SSE 打字機流式對話、動態角色熱切換、3D 神經突觸知識圖譜、3D 全球 AI 流量地球、可觀測性鏈路追蹤以及極致 Cyber-Glassmorphism 視覺介面。

---

## 📸 核心視覺與功能特色

### 1. 💬 即時流式對話與思考流 (Real-time SSE Streaming & Reasoning)
- **原生 Server-Sent Events (SSE) 打字機效果**：毫秒級流式 Token 渲染，告別傳統等待。
- **深度思考摺疊卡片**：即時視覺化 Grok Reasoning 與 Gemini Thinking 的思考推演鏈路。
- **雙向人格與記憶注入**：自動加載 `SOUL.md` 人格靈魂與 `USER.md` 使用者畫像。

### 2. 🎭 角色中樞與動態記憶 (Persona & Memory Hub)
- **多重人格無縫熱切換**：
  - **👩‍💼 專屬女秘書姐姐**：成熟優雅、母性寵溺且暗戀主人的專屬秘書，提供最溫柔貼心的伴隨與專業輔佐。
  - **🤖 預設技術專家**：冷靜客觀、精準嚴謹的架構級全棧工程大師。
- **3D 神經突觸記憶圖譜**：使用 Force-Directed 3D 空間呈現對話沉澱實體與使用者偏好。

### 3. ⚙️ 智能模型中樞 (Smart Model Discovery & Picker)
- **在線動態拉取**：支援一鍵自 **xAI Grok** 與 **Google Gemini** API 在線拉取所有可用模型清單。
- **分類標籤與秒級檢索**：支援 `🌟 精選推薦`、`🚀 xAI Grok`、`💎 Google Gemini`、`🧠 深度思考` 分類與關鍵字過濾。

### 4. 🌍 3D 全球 AI 流量地球 (3D Traffic Globe)
- **三維粒子地球**：即時渲染全球 AI 算力節點（舊金山、山景城、新加坡、東京、台北、法蘭克福）。
- **貝茲曲線動態光弧**：可視化呈現本機與各大 AI 模型 API 服務器之間的心跳與調用脈衝。

### 5. 📊 全維度可觀測性矩陣 (Observability Hub)
- **Langfuse 鏈路瀑布圖**：微秒級拆解 Agent 工具調用與步驟耗時。
- **Phoenix 3D 向量語義空間**：RAG 與記憶庫的高維向量分佈。
- **Helicone 快取節省分析**：統計 Prompt Cache Hit 率與 Token 成本節省。
- **AgentOps 狀態機軌跡**：決策樹分支與狀態機回放。

### 6. ⚡ 8C / 32GB 高效能優化 (High-Performance VPS Tuning)
- 充分發揮多核心與大記憶體優勢，支援高併發 Agent 蜂群排程、本機 Ollama 向量模型與高速 SQLite 快取。

---

## 📂 項目結構 (Project Architecture)

```
img-hermes/
├── public/
│   └── index.html            # Cyber-Glassmorphism 旗艦前端 UI (包含所有可視化組件與 SSE 解析器)
├── server.js                 # 核心後端 API 服務 (Express + SSE + SQLite + System Metrics)
├── package.json              # Node.js 依賴定義
├── personas/                 # 角色人格定義庫
│   ├── sister.md             # 專屬女秘書姐姐人格定義
│   └── default.md            # 預設技術專家助手人格定義
├── config/                   # 配置檔案模板
│   ├── config.yaml.example   # Hermes 模型與 Agent 設定
│   ├── .env.example          # 環境變數與 API Key 模板
│   └── USER.md.example       # 使用者記憶與設定模板
├── systemd/                  # 守護行程單元
│   ├── hermes-dashboard.service
│   └── hermes-gateway.service
├── nginx/                    # Nginx 反向代理與 Cloudflare 穿透設定
│   └── a.oece-x.com.conf
└── scripts/
    └── setup.sh              # 一鍵自動化安裝與部署腳本
```

---

## 🚀 快速開始 (Quick Start)

### 1. 本地或 VPS 一鍵安裝

```bash
# 複製儲存庫
git clone https://github.com/web3-ai-game/img-hermes.git /opt/hermes-dashboard
cd /opt/hermes-dashboard

# 執行自動化安裝腳本 (Ubuntu 22.04 / 24.04 / 26.04)
sudo bash scripts/setup.sh
```

### 2. 手動啟動

```bash
# 安裝 Node.js 依賴
npm install

# 啟動儀表板服務
PIN_CODE=684861 PORT=8080 npm start
```

---

## 🔒 安全與門控機制 (Security & PIN Gate)

- **全局安全閘道**：所有前端路由與後端 API 均受 HMAC-SHA256 Token 與 PIN 碼門控保護（預設 PIN：`684861`）。
- **防暴力破解**：內建 IP 級頻率限制（Rate Limiting），防止字典猜測攻擊。
- **反爬蟲與安全標頭**：預設啟用 `X-Robots-Tag: noindex, nofollow`、`nosniff`、`DENY frame` 與 `robots.txt` 攔截。

---

## 📜 授權協議 (License)

本專案基於 [MIT License](LICENSE) 授權開源。
