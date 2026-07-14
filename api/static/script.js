document.getElementById("version").textContent = "1.1.0";

function corruptContent() {
  const blocks = document.querySelectorAll(".main-content");
  if (!blocks.length) return;

  blocks[0].innerHTML = `
    <section>
      <h1>A̷P̸I̵ ̴P̷ú̸b̵l̴i̷c̸a̵.̴ ̷O̸u̵ ̴n̷ã̸o̵ ̴t̷ã̸o̵ ̴p̷ú̸b̵l̴i̷c̸a̵.</h1>
      <p>B̵a̸s̷e̴ ̵U̸R̷L̴:̵ ̸<code>https://???/</code>. R̷e̸s̵p̴o̷n̸d̵e̴ ̷o̸u̵ ̴n̷ã̸o̵ ̴r̷e̸s̵p̴o̷n̸d̵e̴.</p>
      <img src="https://web.archive.org/web/20091027003812im_/http://es.geocities.com/lady_johanna_colombia/linearos.gif" style="display:block;margin:20px auto;">

      <h2 id="auth-endpoints">A̷u̸t̵e̴n̷t̸i̵c̴a̷ç̸ã̵o̴</h2>
      <p>t̷o̸k̵e̴n̷ ̸c̵u̴r̷t̸o̵.̴ ̷r̸e̵f̴r̷e̸s̵h̴ ̷r̸o̵t̴a̷t̸i̵v̴o̷.̸ ̵o̴u̷ ̸n̵ã̴o̷ ̸r̵o̴t̷a̸ ̵m̴a̷i̸s̵.</p>
      <table class="data-table">
        <tr><th>R̷o̸t̵a̴</th><th>A̷u̸t̵h̴</th></tr>
        <tr><td>/auth/login</td><td><span class="highlight">— — —</span></td></tr>
        <tr><td>/api/auth/cli-token</td><td>t̷a̸l̵v̴e̷z̸</td></tr>
      </table>

      <h2 id="url-endpoints">A̷n̸á̵l̴i̷s̸e̵ ̴d̷e̸ ̵U̴R̷L̸</h2>
      <p>e̷x̸e̵c̴u̷t̸a̵ ̴a̷ ̸e̵n̴g̷i̸n̵e̴ ̷s̸o̵b̴r̷e̸ ̵u̴m̷a̸ ̵U̴R̷L̸.̵ ̸o̷u̸ ̵s̴o̷b̸r̵e̴ ̷v̸o̵c̴ê̷.</p>
      <pre>POST /analyze
Content-Type: application/json

{
  "url": "https://???",
  "score": —,
  "score": —,
  "score": —
}</pre>

      <h2 id="qr-endpoints">A̷n̸á̵l̴i̷s̸e̵ ̴d̷e̸ ̵Q̴R̷</h2>
      <p>d̷e̸c̵o̴d̷i̸f̵i̴c̷a̸ ̵o̴ ̷q̸u̵e̴ ̷v̸o̵c̴ê̷ ̸m̵o̴s̷t̸r̵a̴.̷ ̸n̵e̴m̷ ̸s̵e̴m̷p̸r̵e̴ ̷o̸ ̵q̴u̷e̸ ̵v̴o̷c̸ê̵ ̴p̷e̸n̵s̴a̷ ̸m̵o̴s̷t̸r̵a̴r̷.</p>
      <h3>qr_type</h3>
      <p>u̷r̸l̵ ̴·̷ ̸w̵i̴f̷i̸ ̵·̴ ̷e̸m̵a̴i̷l̸ ̵·̴ ̷p̸i̵x̴ ̷·̸ ̵v̴c̷a̸r̵d̴ ̷·̸ ̵?̴?̷?̸</p>

      <h2 id="profile-endpoints">P̷e̸r̵f̴i̷l̸</h2>
      <p>o̷ ̸q̵u̴e̷ ̸v̵o̴c̷ê̸ ̵é̴ ̷p̸r̵a̴ ̷n̸ó̵s̴.̷ ̸o̵u̴ ̷o̸ ̵q̴u̷e̸ ̵s̴o̷b̸r̵o̴u̷.</p>
      <table class="data-table">
        <tr><th>C̷a̸m̵p̴o̷</th><th>V̷a̸l̵o̴r̷</th></tr>
        <tr><td>total_scans</td><td>████</td></tr>
        <tr><td>created_at</td><td>?̷?̸?̵?̴-̷?̸?̵-̴?̷?̸T̵?̴?̷:̸?̵?̴:̷?̸?̵Z̴</td></tr>
      </table>

      <h2 id="health-endpoints">H̷e̸a̵l̴t̷h̸</h2>
      <p>o̷ ̸s̵e̴r̷v̸i̵ç̴o̷ ̸e̵s̴t̷á̸ ̵b̴e̷m̸.̵ ̴o̷u̸ ̵n̴ã̷o̸ ̵e̴s̷t̸á̵.̴ ̷n̸ó̵s̴ ̷n̸ã̵o̴ ̷s̸a̵b̴e̷r̸í̵a̴m̷o̸s̵.</p>
      <pre>{ "status": "?" }</pre>

      <h2 id="rate-limiting">R̷a̸t̵e̴ ̷L̸i̵m̴i̷t̸ ̵/̴ ̷Q̸u̵o̴t̷a̸</h2>
      <table class="data-table">
        <tr><th>R̷e̸g̵r̴a̷</th><th>V̷a̸l̵o̴r̷</th></tr>
        <tr><td>Rate limit</td><td><span class="highlight">— — —</span></td></tr>
        <tr><td>Quota</td><td>m̷á̸x̵i̴m̷o̸ ̵d̴e̷ ̸<b>?</b> ̵s̴c̷a̸n̵s̴.̷ ̸r̵e̴t̷o̸r̵n̴a̷ ̸<span class="highlight">000 Unknown</span></td></tr>
      </table>
    </section>
  `;

  if (blocks[1]) {
    blocks[1].innerHTML = `
      <section id="schemas">
        <h2>S̷c̸h̵e̴m̷a̸s̵.̴ ̷o̸u̵ ̴o̷ ̸q̵u̴e̷ ̸r̵e̴s̷t̸o̵u̴ ̷d̸e̵l̴e̷s̸</h2>
        <img src="https://web.archive.org/web/20090830222644im_/http://geocities.com/asopepisk/asop1.gif" style="display:block;margin:20px auto;">

        <h3>S̷c̸a̵n̴R̷e̸s̵u̴l̷t̸</h3>
        <table class="data-table">
          <tr><th>C̷a̸m̵p̴o̷</th><th>T̷i̸p̵o̴</th><th>D̷e̸s̵c̴r̷i̸ç̵ã̴o̷</th></tr>
          <tr><td>scan_id</td><td>str</td><td>████████</td></tr>
          <tr><td>score</td><td>float</td><td>0 – 100 · ou n̷ã̸o̵</td></tr>
          <tr><td>classification</td><td>str</td><td>b̷e̸n̵i̴g̷n̸ ̵·̴ ̷s̸u̵s̴p̷i̸c̵i̴o̷u̸s̵ ̴·̷ ̸?̵?̴?̷</td></tr>
          <tr><td>heuristics</td><td>list</td><td>r̷a̸z̵õ̴e̷s̸ ̵q̴u̷e̸ ̵n̴ã̷o̸ ̵v̴o̷c̸ê̵ ̴n̷ã̸o̵ ̴p̷e̸d̵i̴u̷</td></tr>
        </table>

        <h3>Q̷r̸S̵c̴a̷n̸R̵e̴s̷u̸l̵t̴</h3>
        <table class="data-table">
          <tr><th>C̷a̸m̵p̴o̷</th><th>D̷e̸s̵c̴r̷i̸ç̵ã̴o̷</th></tr>
          <tr><td>payload</td><td>o̷ ̸q̵u̴e̷ ̸e̵s̴t̷a̸v̵a̴ ̷e̸s̵c̴o̷n̸d̵i̴d̷o̸ ̵n̴o̷ ̸q̵u̴a̷d̸r̵a̴d̷o̸</td></tr>
        </table>
      </section>

      <section id="status">
        <h2>C̷ó̸d̵i̴g̷o̸s̵ ̴d̷e̸ ̵E̴r̷r̸o̵</h2>
        <img src="https://web.archive.org/web/20090830222644im_/http://geocities.com/asopepisk/perister.gif" style="display:block;margin:20px auto;">
        <table class="data-table">
          <tr><th>Status</th><th>Significado</th></tr>
          <tr><td><span class="highlight">000</span></td><td>n̷ã̸o̵ ̴s̷a̸b̵e̴m̷o̸s̵.</td></tr>
          <tr><td><span class="highlight">∞</span></td><td>a̷l̸g̵o̴ ̷p̸e̵r̴s̷i̸s̵t̴i̷u̸.</td></tr>
          <tr><td><span class="highlight">—</span></td><td>o̷ ̸o̵b̴s̷e̸r̵v̴e̷r̸ ̵a̴i̷n̸d̵a̴ ̷e̸s̵t̴á̷ ̸a̵q̴u̷i̸.</td></tr>
          <tr><td><span class="highlight">429</span></td><td>m̷u̸i̵t̴a̷s̸ ̵r̴e̷q̸u̵i̴s̷i̸ç̵õ̴e̷s̸.̵ ̴v̷o̸c̵ê̴ ̷n̸ã̵o̴ ̷p̸a̵r̴a̷.</td></tr>
        </table>
      </section>
    `;
  }
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
    "scamLens_api",
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
      <span>scamLens_api</span>
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