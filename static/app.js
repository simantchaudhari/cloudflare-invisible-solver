let solving = false;

async function solveChallenge() {
  if (solving) return;

  const url     = document.getElementById('url-input').value.trim();
  const proxies = document.getElementById('proxies-input').value.trim();

  if (!url) { flash('url-input'); return; }
  if (!url.includes('/cdn-cgi/challenge-platform/scripts/jsd/main.js')) {
    flash('url-input');
    return;
  }

  setSolving(true);
  const t0 = Date.now();

  let apiUrl = `/solve?url=${encodeURIComponent(url)}`;
  if (proxies) apiUrl += `&proxies=${encodeURIComponent(proxies)}`;

  let data;
  try {
    const r = await fetch(apiUrl);
    data = await r.json();
  } catch (e) {
    data = { success: false, error: `Network error: ${e.message}` };
  }

  const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
  setSolving(false);
  render(data, elapsed);
}

function render(data, elapsed) {
  const results = document.getElementById('results');
  results.style.display = 'flex';
  results.className = 'fade-in';

  const badge      = document.getElementById('status-badge');
  const errDetail  = document.getElementById('error-detail');
  const errText    = document.getElementById('error-text');
  const fields     = document.getElementById('result-fields');
  const cfbmBlock  = document.getElementById('cfbm-block');

  if (data.success) {
    badge.innerHTML = `
      <span class="badge-success">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.5"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Challenge Solved Successfully &nbsp;·&nbsp; ${elapsed}s
      </span>`;

    errDetail.style.display = 'none';
    fields.style.display    = 'flex';
    fields.style.flexDirection = 'column';
    fields.style.gap        = '12px';

    document.getElementById('cf-val').textContent   = data.cf_clearance || '';
    document.getElementById('ua-val').textContent   = data.user_agent   || '';
    document.getElementById('json-val').textContent = JSON.stringify(data, null, 2);

    if (data.__cf_bm) {
      cfbmBlock.style.display = 'block';
      document.getElementById('cfbm-val').textContent = data.__cf_bm;
    } else {
      cfbmBlock.style.display = 'none';
    }

  } else {
    badge.innerHTML = `
      <span class="badge-error">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
          <line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          <line x1="9"  y1="9" x2="15" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
        Solve Failed &nbsp;·&nbsp; ${elapsed}s
      </span>`;

    errText.textContent     = data.error || 'Unknown error.';
    errDetail.style.display = 'block';
    fields.style.display    = 'none';
  }

  setTimeout(() => results.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 80);
}

/* ── helpers ── */
function setSolving(on) {
  solving = on;
  const btn     = document.getElementById('solve-btn');
  const label   = document.getElementById('btn-label');
  const spinner = document.getElementById('btn-spinner');
  btn.disabled        = on;
  label.textContent   = on ? 'Solving…' : 'Solve Challenge';
  spinner.style.display = on ? 'block' : 'none';
}

function flash(id) {
  const el = document.getElementById(id);
  el.style.transition  = 'none';
  el.style.borderColor = '#ef4444';
  el.style.boxShadow   = '0 0 0 3px rgba(239,68,68,0.15)';
  setTimeout(() => {
    el.style.transition  = 'border-color 0.4s, box-shadow 0.4s';
    el.style.borderColor = '';
    el.style.boxShadow   = '';
  }, 600);
}

function copyVal(id, btn) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
  });
}

/* Enter key */
document.addEventListener('DOMContentLoaded', () => {
  ['url-input', 'proxies-input'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', e => {
      if (e.key === 'Enter') solveChallenge();
    });
  });
});
