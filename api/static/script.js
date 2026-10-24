"use strict";

// ScamLens: documentação normal até que o visitante descubra o segredo.
// O modo secreto é intencionalmente surreal, mas não é executado por padrão.
const EGG_STORAGE_KEY = "scamlens:easter-egg:seen";
const EGG_SEQUENCE = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"];
let eggActive = false;
const eggIntervals = new Set();

function registerEggInterval(callback, delay) {
  const id = window.setInterval(callback, delay);
  eggIntervals.add(id);
  return id;
}

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
    a.rel = "noopener noreferrer";
  });

  document.querySelectorAll("footer a").forEach(a => {
    if (!a.href.includes("github")) {
      a.href = weirdSites[Math.floor(Math.random() * weirdSites.length)];
      a.target = "_blank";
    a.rel = "noopener noreferrer";
    }
  });

  document.querySelectorAll(".main-content a").forEach(a => {
    a.href = weirdSites[Math.floor(Math.random() * weirdSites.length)];
    a.target = "_blank";
    a.rel = "noopener noreferrer";
  });

  document.querySelectorAll(".main-content p, .main-content td").forEach(el => {
    if (Math.random() < 0.4) {
      const url = weirdSites[Math.floor(Math.random() * weirdSites.length)];
      el.style.cursor = "pointer";
      el.addEventListener("click", () => window.open(url, "_blank", "noopener,noreferrer"));
    }
  });
}

function decayText(registerInterval) {
  const chars = ["█", "░", "?", "⟁", "☍", "▓", "⌘", "π", "⓿"];
  registerInterval(() => {
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


function showReturnPopup() {
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

  window.setTimeout(() => {
    overlay.appendChild(popup);
    document.body.appendChild(overlay);
    document.getElementById("popup-close").addEventListener("click", () => overlay.remove());
    document.getElementById("popup-ok").addEventListener("click", () => overlay.remove());
  }, 400 + Math.random() * 900);
}


// A anomalia progride em estágios; todos os efeitos ficam isolados no modo secreto.
function startLivingCorruption() {
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const veil = document.createElement('div');
  veil.className = 'egg-veil';
  veil.setAttribute('aria-hidden', 'true');
  veil.innerHTML = '<div class="egg-scanlines"></div><div class="egg-noise"></div><div class="egg-terminal"></div><div class="egg-ghost"></div>';
  document.body.appendChild(veil);
  const terminal = veil.querySelector('.egg-terminal');
  const ghost = veil.querySelector('.egg-ghost');
  const phrases = [
    'MEMORY LEAK // 0x000000', 'THIS PAGE IS NOT A PAGE',
    'DO NOT TRUST THE SCORE', 'THE OBSERVER IS STILL HERE',
    'SCAMLENS.EXE HAS STOPPED RESPONDING', 'PACKET LOST // YOU FOUND ME',
    'CACHE CORRUPTED', 'I CAN SEE THE CURSOR', 'RETRYING REALITY...'
  ];
  const random = (min, max) => min + Math.random() * (max - min);
  let stage = 0;
  let tick = 0;
  let pointerX = innerWidth / 2;
  let pointerY = innerHeight / 2;
  document.body.classList.add('egg-active');
  const updatePointer = event => { pointerX = event.clientX; pointerY = event.clientY; };
  document.addEventListener('pointermove', updatePointer, { passive: true });

  const burst = () => {
    if (reducedMotion) return;
    const fragment = document.createElement('span');
    fragment.className = 'egg-fragment';
    fragment.textContent = phrases[Math.floor(Math.random() * phrases.length)];
    fragment.style.left = `${random(3, 75)}vw`;
    fragment.style.top = `${random(4, 90)}vh`;
    fragment.style.fontSize = `${random(10, 22)}px`;
    fragment.style.setProperty('--skew', `${random(-10, 10)}deg`);
    veil.appendChild(fragment);
    window.setTimeout(() => fragment.remove(), 700);
  };
  const pulse = () => {
    tick++;
    if (tick % 12 === 0 && stage < 3) {
      stage++;
      document.body.dataset.eggStage = String(stage);
    }
    terminal.textContent = `SCAMLENS / ${String(tick).padStart(4, '0')}  //  ${phrases[Math.floor(Math.random() * phrases.length)]}`;
    ghost.textContent = phrases[Math.floor(Math.random() * phrases.length)];
    ghost.style.left = `${Math.max(5, Math.min(innerWidth - 230, pointerX + random(-160, 90)))}px`;
    ghost.style.top = `${Math.max(10, Math.min(innerHeight - 50, pointerY + random(-100, 80)))}px`;
    if (!reducedMotion && Math.random() < 0.25 + stage * 0.12) burst();
    if (!reducedMotion && Math.random() < 0.18 + stage * 0.1) {
      document.body.classList.add('egg-impact');
      window.setTimeout(() => document.body.classList.remove('egg-impact'), 120);
    }
    document.documentElement.style.setProperty('--egg-shift', `${Math.round(random(-stage * 3, stage * 3))}px`);
  };
  pulse();
  registerEggInterval(pulse, reducedMotion ? 2400 : 650);
  // O visitante sempre pode sair do modo secreto com Escape.
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') window.location.reload();
  });
}


// Web 1.0: GIFs decorativos remotos; a página continua funcionando sem eles.
function startRetroChaos() {
  const gifs = [
    'https://upload.wikimedia.org/wikipedia/commons/2/2c/Rotating_earth_%28large%29.gif',
    'https://upload.wikimedia.org/wikipedia/commons/1/14/Animated-Flag-USA.gif',
    'https://upload.wikimedia.org/wikipedia/commons/8/89/HD_transparent_picture.gif'
  ];
  const labels = ['UNDER CONSTRUCTION', 'WELCOME TO MY HOMEPAGE', '404 REALITY NOT FOUND', 'BEST VIEWED IN 1999', 'YOU ARE VISITOR #000666', 'SIGN MY GUESTBOOK'];
  const intro = document.querySelector('.main-content');
  if (intro) {
    const strip = document.createElement('div');
    strip.className = 'egg-retro-strip';
    const title = document.createElement('strong');
    title.textContent = '★ THE INTERNET IS HAUNTED ★';
    strip.append(title);
    for (const src of gifs) {
      const img = document.createElement('img');
      img.src = src; img.alt = 'GIF retrô'; img.loading = 'lazy';
      img.onerror = () => img.remove();
      strip.append(img);
    }
    const ticker = document.createElement('marquee');
    ticker.textContent = '★ UNDER CONSTRUCTION ★ DO NOT FEED THE WEBMASTER ★ YOUR MODEM IS SCREAMING ★';
    ticker.setAttribute('scrollamount', '8');
    strip.append(ticker);
    intro.prepend(strip);
  }
  let visits = 666;
  const counter = document.createElement('div');
  counter.className = 'egg-counter';
  counter.textContent = 'VISITORS: 000666';
  document.body.append(counter);
  registerEggInterval(() => { counter.textContent = 'VISITORS: ' + String(++visits).padStart(6, '0'); }, 1200);
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  registerEggInterval(() => {
    if (document.querySelectorAll('.egg-sticker').length >= 6) return;
    const el = document.createElement('div');
    el.className = 'egg-sticker';
    el.style.left = Math.floor(Math.random() * 85) + 'vw';
    el.style.top = Math.floor(Math.random() * 80) + 'vh';
    if (Math.random() < 0.5) {
      const img = document.createElement('img');
      img.src = gifs[Math.floor(Math.random() * gifs.length)];
      img.alt = '';
      img.style.cssText = 'width:100%;height:100%;object-fit:contain';
      img.onerror = () => el.remove();
      el.append(img);
    } else {
      el.style.cssText += ';width:180px;height:auto;background:yellow;border:3px ridge red;color:blue;font:bold 16px "Comic Sans MS",serif;padding:5px';
      el.textContent = labels[Math.floor(Math.random() * labels.length)];
    }
    document.body.append(el);
    window.setTimeout(() => el.remove(), 3200);
  }, 1100);
}

function activateEasterEgg() {
  if (eggActive) return;
  eggActive = true;
  try { localStorage.setItem(EGG_STORAGE_KEY, "1"); } catch (_) { /* armazenamento indisponível */ }

  document.body.style.backgroundImage = "url('https://i.pinimg.com/originals/1f/1a/f7/1f1af705467aa7d5df2264d21fc23fe2.gif')";
  document.body.style.backgroundRepeat = "repeat";
  document.body.style.backgroundAttachment = "fixed";
  document.getElementById("version")?.replaceChildren("???????????????????????");
  document.getElementById("message")?.replaceChildren("Why did you do that?");
  corruptContent();
  corruptLinks();
  decayText(registerEggInterval);
  startLivingCorruption();
  startRetroChaos();
  document.title = "Maybe I'm not doing so well after all.";

  const logo = document.querySelector(".logo-text");
  if (logo) {
    logo.textContent = "⟁ᚫ⟁ ::: ░▒▓ ☍☌☍ ▓▒░ ::: ϞϞϞ";
    logo.href = "https://www.cameronsworld.net/";
    logo.target = "_blank";
    logo.rel = "noopener noreferrer";
  }
  document.getElementById("desc")?.replaceChildren("You know what I mean?");

  const titles = ["Maybe I'm not doing so well after all.", "scamLens_api", "you left this open.", "don't look away."];
  let titleIndex = 0;
  registerEggInterval(() => { document.title = titles[titleIndex++ % titles.length]; }, 900);
  if (!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
    registerEggInterval(() => { if (Math.random() < 0.25) glitch(); }, 2000);
  }

  window.setTimeout(() => {
    const audio = new Audio("/static/Blue_Skies.mp3");
    audio.volume = 0.2;
    audio.play().catch(() => { /* autoplay pode ser bloqueado */ });
  }, 3000);
}

function setupEasterEgg() {
  let buffer = [];
  document.addEventListener("keydown", event => {
    if (eggActive || event.repeat || event.altKey || event.ctrlKey || event.metaKey) return;
    if (event.target instanceof HTMLElement && event.target.closest("input, textarea, select, [contenteditable]")) return;
    buffer.push(event.key.length === 1 ? event.key.toLowerCase() : event.key);
    buffer = buffer.slice(-EGG_SEQUENCE.length);
    if (EGG_SEQUENCE.every((key, index) => key === buffer[index])) activateEasterEgg();
  });

  const logo = document.querySelector(".logo-text");
  if (logo) {
    let taps = 0;
    let tapTimer;
    logo.addEventListener("touchstart", event => {
      if (eggActive) return;
      event.preventDefault();
      taps++;
      clearTimeout(tapTimer);
      tapTimer = window.setTimeout(() => { taps = 0; }, 1500);
      if (taps >= 7) { taps = 0; activateEasterEgg(); }
    }, { passive: false });
  }

  let seen = false;
  try { seen = localStorage.getItem(EGG_STORAGE_KEY) === "1" || localStorage.getItem("seen") === "1"; } catch (_) {}
  if (seen) {
    const messages = ["you again?", "strange.", "I remember this window.", "something persisted.", "there you are.", "still here?", "this wasn't here before.", "it kept your session.", "I thought this instance was closed.", "you returned too early.", "...", "the cache survived.", "didn't this end already?", "there is residual activity.", "the observer remembers."];
    if (Math.random() < 0.65) document.title = messages[Math.floor(Math.random() * messages.length)];
    showReturnPopup();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", setupEasterEgg, { once: true });
} else {
  setupEasterEgg();
}
