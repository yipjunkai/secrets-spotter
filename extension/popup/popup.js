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

    statusEl.textContent = '';
    const statusSmall = document.createElement('small');
    statusSmall.textContent = `${scannedCount} scanned, ${skippedCount} skipped${sourceBreakdown ? ` (${sourceBreakdown})` : ''}`;
    statusEl.appendChild(statusSmall);

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

    summaryEl.textContent = '';
    const strong = document.createElement('strong');
    strong.textContent = `${findings.length} secret(s) detected`;
    summaryEl.appendChild(strong);
    summaryEl.appendChild(document.createElement('br'));
    const entries = Object.entries(grouped);
    entries.forEach(([s, c], i) => {
      const span = document.createElement('span');
      span.className = `severity-${s.toLowerCase()}`;
      span.textContent = `${s}: ${c}`;
      summaryEl.appendChild(span);
      if (i < entries.length - 1) {
        summaryEl.appendChild(document.createTextNode(' | '));
      }
    });

    for (const f of findings) {
      const li = document.createElement('li');
      li.className = `finding severity-${f.severity.toLowerCase()}`;
      const sourceLabel = f.source?.startsWith('network:') ? `[${f.source.replace('network:', '').toUpperCase()}]` : '[DOM]';

      const header = document.createElement('strong');
      header.appendChild(document.createTextNode(f.label + ' '));
      const headerSmall = document.createElement('small');
      headerSmall.textContent = sourceLabel;
      header.appendChild(headerSmall);

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

  const debugSection = document.getElementById('debug-section');
  const debugContent = document.getElementById('debug-log-content');
  const clearBtn = document.getElementById('clear-log-btn');

  debugSection.addEventListener('toggle', () => {
    if (!debugSection.open) return;
    chrome.runtime.sendMessage({ type: 'GET_ERROR_LOG' }, (res) => {
      const logs = res?.errorLog || [];
      if (logs.length === 0) {
        debugContent.textContent = 'No errors logged.';
        clearBtn.classList.add('hidden');
        return;
      }
      clearBtn.classList.remove('hidden');
      debugContent.innerHTML = '';
      for (const entry of logs.slice().reverse()) {
        const div = document.createElement('div');
        div.className = 'log-entry';
        const time = new Date(entry.ts).toLocaleTimeString();
        div.textContent = `[${time}] [${entry.src}] ${entry.msg}`;
        if (entry.url) {
          div.title = entry.url;
        }
        debugContent.appendChild(div);
      }
    });
  });

  clearBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'CLEAR_ERROR_LOG' }, () => {
      debugContent.textContent = 'No errors logged.';
      clearBtn.classList.add('hidden');
    });
  });
});
