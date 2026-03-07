document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  function renderFindings(data) {
    if (chrome.runtime.lastError) {
      console.warn('Secrets Spotter:', chrome.runtime.lastError.message);
      return;
    }
    const findings = data?.findings || [];
    const summaryEl = document.getElementById('summary');
    const listEl = document.getElementById('findings-list');
    const noFindingsEl = document.getElementById('no-findings');
    const statusEl = document.getElementById('status');

    const scannedCount = data?.scannedCount || 0;
    const skippedCount = data?.skippedCount || 0;
    const sources = data?.sources || {};
    const sourceBreakdown = Object.entries(sources)
      .map(([s, c]) => `${s}: ${c}`)
      .join(', ');

    statusEl.innerHTML = `<small>${scannedCount} scanned, ${skippedCount} skipped${sourceBreakdown ? ` (${sourceBreakdown})` : ''}</small>`;

    listEl.innerHTML = '';
    noFindingsEl.classList.add('hidden');

    if (findings.length === 0) {
      noFindingsEl.classList.remove('hidden');
      summaryEl.textContent = 'No secrets found.';
      return;
    }

    const grouped = {};
    for (const f of findings) {
      grouped[f.severity] = (grouped[f.severity] || 0) + 1;
    }

    summaryEl.innerHTML = `
      <strong>${findings.length} secret(s) detected</strong><br>
      ${Object.entries(grouped)
        .map(([s, c]) => `<span class="severity-${s.toLowerCase()}">${s}: ${c}</span>`)
        .join(' | ')}
    `;

    for (const f of findings) {
      const li = document.createElement('li');
      li.className = `finding severity-${f.severity.toLowerCase()}`;
      const sourceLabel = f.source?.startsWith('network:') ? `[${f.source.replace('network:', '').toUpperCase()}]` : '[DOM]';

      const header = document.createElement('strong');
      header.innerHTML = `${f.label} <small>${sourceLabel}</small>`;

      const codeRow = document.createElement('div');
      codeRow.className = 'code-row';

      const code = document.createElement('code');
      code.textContent = f.full_match;

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(f.full_match).then(() => {
          copyBtn.textContent = 'Copied!';
          setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
        });
      });

      codeRow.appendChild(code);
      codeRow.appendChild(copyBtn);
      li.appendChild(header);
      li.appendChild(codeRow);

      if (f.sourceUrl && f.sourceUrl !== (data?.url || '')) {
        const srcUrl = document.createElement('div');
        srcUrl.className = 'source-url';
        srcUrl.textContent = f.sourceUrl;
        li.appendChild(srcUrl);
      }

      listEl.appendChild(li);
    }
  }

  function fetchFindings() {
    chrome.runtime.sendMessage(
      { type: 'GET_FINDINGS', tabId: tab.id },
      renderFindings
    );
  }

  fetchFindings();
});
