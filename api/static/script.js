document.getElementById("version").textContent = "1.0.9";

function corruptContent() {
  const content = document.querySelector(".main-content");
  content.innerHTML = `
    <section>
      <h1>R̷e̸f̵e̴r̷ê̴n̸c̵i̴a̷ ̸d̵a̴ ̷A̸P̵I̴</h1>
      <p>B̵a̸s̷e̴ ̵U̸R̷L̴ ̵p̸a̷r̴a̵ ̸t̷o̴d̵a̸s̷ ̴a̵s̸ ̷r̴e̵q̸u̷i̴s̵i̸ç̷õ̴e̵s̸:̷ ̴<code>https://???/</code></p>
      <img src="https://web.archive.org/web/20091027003812im_/http://es.geocities.com/lady_johanna_colombia/linearos.gif" style="display:block;margin:20px auto;">
      <h3>Autenticação & Limites</h3>
      <p>A API n̷ã̸o̵ ̸é̷ ̴p̵ú̸b̷l̴i̵c̸a̷. O controle é feito via ███████ por endereço ██.</p>
      <table class="data-table">
        <tr><th>Recurso</th><th>Configuração / Resposta</th></tr>
        <tr><td>Rate Limit</td><td><span class="highlight">— — —</span></td></tr>
        <tr><td>Concorrência</td><td>Máximo de <b>?</b> scans. Retorna <span class="highlight">000 Unknown</span>.</td></tr>
      </table>
    </section>

    <section>
      <h2>Endpoints D̵i̸s̷p̴o̵n̸í̷v̴e̵i̸s̷</h2>
      <img src="https://web.archive.org/web/20090831183350im_/http://geocities.com/kiwanisbaseball/_derived/13_year_old.htm_cmp_zero010_bnr.gif" style="display:block;margin:20px auto;">
      <h3>POST /analyze</h3>
      <p>E̷x̸e̵c̴u̷t̸a̵ ̴a̷ ̸e̵n̴g̷i̸n̵e̴ ̷s̸o̵b̴r̷e̸ ̵u̴m̷a̸ ̵U̴R̷L̸ ̵e̴s̷p̸e̵c̴í̷f̸i̵c̴a̷.̸ ̵O̴u̷ ̸n̵ã̴o̷.</p>
      <pre>POST /analyze
Content-Type: application/json

{
  "url": "https://???",
  "use_cache": true,
  "use_cache": true,
  "use_cache": true
}</pre>
      <h3>GET /scans</h3>
      <p>R̷e̸t̵o̴r̷n̸a̵ ̴l̷i̸s̵t̴a̷ ̸d̵e̴ ̷a̸n̵á̴l̷i̸s̵e̴s̷ ̴r̵e̸c̷e̴n̵t̸e̷s̴.̵ ̸o̷u̴ ̵n̸ã̷o̴ ̵r̷e̸t̵o̴r̷n̸a̵ ̴n̷a̸d̵a̴.</p>
      <h3>GET /scans/{identifier}</h3>
      <p>identifier não é o que você pensa.</p>
      <h3>GET /health</h3>
      <p>o̷ ̸s̵e̴r̷v̸i̵ç̴o̷ ̸e̵s̴t̷á̸ ̵b̴e̷m̸.̵ ̴o̷u̸ ̵n̵ã̴o̷ ̸e̵s̴t̷á̸.</p>
    </section>

    <section>
      <h2>Schemas d̵e̸ ̷R̴e̵s̸p̷o̴s̵t̸a̷</h2>
      <img src="https://web.archive.org/web/20090830222644im_/http://geocities.com/asopepisk/asop1.gif" style="display:block;margin:20px auto;">
      <pre>{
  "status": "?",
  "engine": { "name": "???", "version": "?" },
  "meta": {
    "scan_id": "████████████████████████████████",
    "scan_time_s": —,
    "url": "https://???",
    "threads": ?,
    "timestamp": "????-??-??T??:??:??.??????+00:00"
  },
  "result": {
    "score": —,
    "risk_level": "unknown",
    "verdict": "???"
  },
  "stats": {
    "rules_total": 0,
    "rules_triggered": 0,
    "trigger_rate": —
  },
  "heuristics": [ ??? ],
  "insight": [ ??? ]
}</pre>
      <h4>heuristics[]</h4>
      <table class="data-table">
        <tr><th>Campo</th><th>Tipo</th><th>Descrição</th></tr>
        <tr><td>n̷a̸m̵e̴</td><td>str</td><td>████████</td></tr>
        <tr><td>c̵a̸t̷e̴g̵o̸r̷y̴</td><td>str</td><td>s̵e̸r̷v̴e̵r̸ · h̵t̸m̷l̴ · u̵r̸l̷ · ???</td></tr>
        <tr><td>value</td><td>float</td><td>0.0 – 1.0 · ou não</td></tr>
        <tr><td>weight</td><td>float</td><td>peso · ou ausência de peso</td></tr>
        <tr><td>contribution</td><td>float</td><td>contribuição · ou nada</td></tr>
        <tr><td>details</td><td>dict</td><td>varia · sempre varia</td></tr>
        <tr><td>reasons</td><td>list[str]</td><td>███ explicações ███</td></tr>
      </table>
    </section>

    <section>
      <h2>T̵a̸r̷g̴e̵t̸R̵e̴s̷p̸o̵n̴s̷e̸</h2>
      <img src="https://web.archive.org/web/20090830222644im_/http://geocities.com/asopepisk/perister.gif" style="display:block;margin:20px auto;">
      <h3>1. Identity</h3>
      <table class="data-table">
        <tr><th>Campo</th><th>Tipo</th><th>Descrição</th></tr>
        <tr><td>original_url</td><td>str</td><td>URL como fornecida · talvez</td></tr>
        <tr><td>final_url</td><td>str|null</td><td>URL após redirecionamentos · se houver</td></tr>
        <tr><td>registered_domain</td><td>str</td><td>domínio registrado · ou não registrado</td></tr>
        <tr><td>is_homograph</td><td>bool</td><td>ataque homograph · ou inocência</td></tr>
        <tr><td>domain_entropy</td><td>float</td><td>entropia · tudo tem entropia</td></tr>
        <tr><td>has_ip</td><td>bool</td><td>IP em vez de domínio · suspeito</td></tr>
      </table>
      <h3>2. Network</h3>
      <table class="data-table">
        <tr><th>Campo</th><th>Descrição</th></tr>
        <tr><td>asn</td><td>número do sistema autônomo · autônomo</td></tr>
        <tr><td>timings</td><td>dns · tcp · tls · ttfb · em milissegundos · ou eternidade</td></tr>
        <tr><td>cdn</td><td>detectado · ou não detectado · ou indetectável</td></tr>
        <tr><td>waf</td><td>firewall · ou ilusão de firewall</td></tr>
      </table>
      <h3>3. TLS</h3>
      <table class="data-table">
        <tr><th>Campo</th><th>Descrição</th></tr>
        <tr><td>enabled</td><td>https · ou http · ou nenhum</td></tr>
        <tr><td>valid_until</td><td>expira · tudo expira</td></tr>
        <tr><td>self_signed</td><td>assinou o próprio certificado · como todos nós</td></tr>
        <tr><td>fingerprints</td><td>sha1 · sha256 · identidade</td></tr>
      </table>
      <h3>4. DNS</h3>
      <table class="data-table">
        <tr><th>Campo</th><th>Descrição</th></tr>
        <tr><td>spf</td><td>configurado · ou não · ou fingindo</td></tr>
        <tr><td>dmarc</td><td>configurado · ou não · ou fingindo</td></tr>
        <tr><td>ttl</td><td>tempo de vida · em segundos · conta regressiva</td></tr>
      </table>
    </section>

    <section>
      <h2>Códigos de Erro</h2>
      <table class="data-table">
        <tr><th>Status</th><th>Significado</th></tr>
        <tr><td><span class="highlight">000</span></td><td>não sabemos.</td></tr>
        <tr><td><span class="highlight">∞</span></td><td>algo persistiu.</td></tr>
        <tr><td><span class="highlight">—</span></td><td>o observer ainda está aqui.</td></tr>
        <tr><td><span class="highlight">400</span></td><td>o engine falhou · como todos falham</td></tr>
        <tr><td><span class="highlight">404</span></td><td>não encontrado · nunca foi encontrado</td></tr>
        <tr><td><span class="highlight">429</span></td><td>muitas requisições · você não para</td></tr>
        <tr><td><span class="highlight">503</span></td><td>ocupado · ou exausto</td></tr>
      </table>
    </section>
  `;
}

function corruptLinks() {
  const weirdSites = [
    "https://omfgdogs.com/",
    "https://www.spacejam.com/1996/",
    "https://www.windows93.net/",
    "https://zombo.com/",
    "https://www.nyan.cat/",
    "https://www.staggeringbeauty.com/",
    "https://www.rrrgggbbb.com/",
    "https://theuselessweb.com/",
    "https://www.fallingfalling.com/",
    "https://heeeeeeeey.com/",
    "https://pointerpointer.com/",
    "https://www.koalastothemax.com/",
  ];

  document.querySelectorAll("nav a").forEach(a => {
    a.href = weirdSites[Math.floor(Math.random() * weirdSites.length)];
    a.target = "_blank";
  });

  document.querySelectorAll("footer a").forEach(a => {
    if (!a.href.includes("github")) {
      a.href = weirdSites[Math.floor(Math.random() * weirdSites.length)];
      a.target = "_blank";
    }
  });

  document.querySelectorAll(".main-content a").forEach(a => {
    a.href = weirdSites[Math.floor(Math.random() * weirdSites.length)];
    a.target = "_blank";
  });

  document.querySelectorAll(".main-content p, .main-content td").forEach(el => {
    if (Math.random() < 0.4) {
      const url = weirdSites[Math.floor(Math.random() * weirdSites.length)];
      el.style.cursor = "pointer";
      el.addEventListener("click", () => window.open(url, "_blank"));
    }
  });
}

function decayText() {
  const chars = ["█", "░", "?", "⟁", "☍", "▓", "⌘", "π", "⓿"];
  setInterval(() => {
    const els = document.querySelectorAll("p, td, h2, h3");
    const el = els[Math.floor(Math.random() * els.length)];
    if (!el) return;
    const textNodes = [...el.childNodes].filter(n => n.nodeType === 3 && n.textContent.trim().length > 0);
    if (!textNodes.length) return;
    const node = textNodes[Math.floor(Math.random() * textNodes.length)];
    const pos = Math.floor(Math.random() * node.textContent.length);
    node.textContent =
      node.textContent.slice(0, pos) +
      chars[Math.floor(Math.random() * chars.length)] +
      node.textContent.slice(pos + 1);
  }, 800);
}

function glitch() {
  const frames = 4;
  let i = 0;
  const interval = setInterval(() => {
    document.body.style.transform = `translateX(${Math.random() * 16 - 8}px)`;
    if (++i >= frames) {
      clearInterval(interval);
      document.body.style.transform = "translateX(0)";
    }
  }, 60);
}

function activateEasterEgg() {
  localStorage.setItem("seen", "1");
  document.body.style.backgroundImage = "url('https://i.pinimg.com/originals/1f/1a/f7/1f1af705467aa7d5df2264d21fc23fe2.gif')";
  document.body.style.backgroundRepeat = "repeat";
  document.body.style.backgroundAttachment = "fixed";
  document.getElementById("version").textContent = "???????????????????????";
  document.getElementById("message").textContent = "Why did you do that?";
  corruptContent();
  corruptLinks();
  decayText();
  document.title = "Maybe I'm not doing so well after all.";

  const titles = [
    "Maybe I'm not doing so well after all.",
    "scurl_api",
    "you left this open.",
    "don't look away."
  ];
  let ti = 0;
  setInterval(() => {
    document.title = titles[ti % titles.length];
    ti++;
  }, 900);

  document.querySelector(".logo-text").textContent = "⟁ᚫ⟁ ::: ░▒▓ ☍☌☍ ▓▒░ ::: ϞϞϞ";
  document.getElementById("link").href = "https://www.cameronsworld.net/";
  document.getElementById("desc").textContent = "You know what I mean?";

  setInterval(() => {
    if (Math.random() < 0.15) glitch();
  }, 2000);

  setTimeout(() => {
    const audio = new Audio("/static/Blue_Skies.mp3");
    audio.volume = 0.2;
    audio.play();
  }, 3000);
}

(function() {
  var _seq = [38,38,40,40,37,39,37,39,66,65];
  var _buf = [];
  document.addEventListener('keydown', function(e) {
    _buf.push(e.keyCode);
    if (_buf.length > _seq.length) _buf.shift();
    if (_buf.length === _seq.length && _buf.every(function(v, i) { return v === _seq[i]; })) {
      activateEasterEgg();
    }
  });
})();

(function() {
  let tapCount = 0;
  let tapTimer;
  document.querySelector(".logo-text").addEventListener("touchstart", (e) => {
    e.preventDefault();
    tapCount++;
    clearTimeout(tapTimer);
    tapTimer = setTimeout(() => tapCount = 0, 1500);
    if (tapCount >= 7) {
      tapCount = 0;
      activateEasterEgg();
    }
  });
})();

const messages = [
  "you again?",
  "strange.",
  "I remember this window.",
  "something persisted.",
  "there you are.",
  "still here?",
  "this wasn't here before.",
  "it kept your session.",
  "I thought this instance was closed.",
  "you returned too early.",
  "...",
  "the cache survived.",
  "didn't this end already?",
  "there is residual activity.",
  "the observer remembers."
];

if (localStorage.getItem("seen")) {
  if (Math.random() < 0.65) {
    document.title = messages[Math.floor(Math.random() * messages.length)];
  }

  const overlay = document.createElement("div");
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0,0,0,0.4);
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
  `;

  const popup = document.createElement("div");
  popup.style.cssText = `
    background: #c0c0c0;
    border-top: 2px solid #fff;
    border-left: 2px solid #fff;
    border-right: 2px solid #404040;
    border-bottom: 2px solid #404040;
    width: 320px;
    font-family: Arial, sans-serif;
    font-size: 12px;
  `;

  popup.innerHTML = `
    <div style="background:#000080;color:#fff;padding:4px 8px;font-size:12px;font-weight:bold;display:flex;justify-content:space-between;align-items:center;">
      <span>scurl_api</span>
      <span id="popup-close" style="cursor:pointer;font-weight:bold;padding:0 4px;border-top:1px solid #fff;border-left:1px solid #fff;border-right:1px solid #404040;border-bottom:1px solid #404040;background:#c0c0c0;color:#000;">✕</span>
    </div>
    <div style="padding:16px 14px;color:#000;line-height:1.6;">
      You came back.<br>I noticed.<br>That was enough.
    </div>
    <div style="padding:0 14px 12px;text-align:right;">
      <button id="popup-ok" style="background:#c0c0c0;border-top:2px solid #fff;border-left:2px solid #fff;border-right:2px solid #404040;border-bottom:2px solid #404040;padding:3px 16px;font-size:12px;cursor:pointer;">OK</button>
    </div>
  `;

  setTimeout(() => {
    overlay.appendChild(popup);
    document.body.appendChild(overlay);
    document.getElementById("popup-close").addEventListener("click", () => overlay.remove());
    document.getElementById("popup-ok").addEventListener("click", () => overlay.remove());
  }, 400 + Math.random() * 900);
}