/**
 * TeraBridge API Documentation — Core Interactivity & Live Sandbox
 */

(function () {
  'use strict';

  // 1. Theme Management
  const root = document.documentElement;
  const themeToggle = document.getElementById('theme-toggle');
  const savedTheme = localStorage.getItem('terabridge-theme') || 'dark';
  root.setAttribute('data-theme', savedTheme);

  function updateThemeButton() {
    const isDark = root.getAttribute('data-theme') === 'dark';
    if (themeToggle) {
      themeToggle.innerHTML = isDark
        ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>`
        : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
    }
  }
  updateThemeButton();

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const nextTheme = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', nextTheme);
      localStorage.setItem('terabridge-theme', nextTheme);
      updateThemeButton();
    });
  }

  // 2. Mobile Sidebar Navigation Toggle
  const sidebar = document.getElementById('docs-sidebar');
  const mobileToggle = document.getElementById('mobile-menu-toggle');
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
    // Close sidebar on link click
    sidebar.addEventListener('click', (e) => {
      if (e.target.closest('a')) {
        sidebar.classList.remove('open');
      }
    });
  }

  // 3. Multi-Language Code Tabs Switching
  document.querySelectorAll('.code-window').forEach((windowEl) => {
    const tabs = windowEl.querySelectorAll('.code-tab');
    const content = windowEl.querySelector('.code-content');
    if (!tabs.length || !content) return;

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        tabs.forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');
        const lang = tab.dataset.lang;
        const snippets = windowEl.querySelectorAll('.code-snippet');
        snippets.forEach((snippet) => {
          if (snippet.dataset.lang === lang) {
            snippet.style.display = 'block';
          } else {
            snippet.style.display = 'none';
          }
        });
      });
    });
  });

  // 4. One-Click Copy to Clipboard
  document.querySelectorAll('.copy-button').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const targetSelector = btn.dataset.target;
      let textToCopy = '';
      if (targetSelector) {
        const target = document.querySelector(targetSelector);
        if (target) textToCopy = target.innerText;
      } else {
        const parentWindow = btn.closest('.code-window');
        if (parentWindow) {
          const visibleSnippet = parentWindow.querySelector('.code-snippet:not([style*="display: none"])') || parentWindow.querySelector('.code-content');
          if (visibleSnippet) textToCopy = visibleSnippet.innerText;
        }
      }

      if (!textToCopy) return;

      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalHTML = btn.innerHTML;
        btn.classList.add('copied');
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Copied`;
        setTimeout(() => {
          btn.innerHTML = originalHTML;
          btn.classList.remove('copied');
        }, 1800);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });
  });

  // 5. ScrollSpy for Sidebar & On-Page Table of Contents
  const sections = Array.from(document.querySelectorAll('.docs-section[id]'));
  const navLinks = Array.from(document.querySelectorAll('.nav-link'));
  const tocLinks = Array.from(document.querySelectorAll('.toc-link'));

  function updateScrollSpy() {
    const scrollPos = window.scrollY + 110;
    let currentId = '';

    for (let i = sections.length - 1; i >= 0; i--) {
      const sec = sections[i];
      if (sec.offsetTop <= scrollPos) {
        currentId = sec.id;
        break;
      }
    }

    if (!currentId && sections.length) {
      currentId = sections[0].id;
    }

    navLinks.forEach((link) => {
      const href = link.getAttribute('href');
      if (href === `#${currentId}`) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    tocLinks.forEach((link) => {
      const href = link.getAttribute('href');
      if (href === `#${currentId}`) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  }

  window.addEventListener('scroll', updateScrollSpy, { passive: true });
  updateScrollSpy();

  // 6. Interactive API Sandbox / Live Request Generator
  const sandboxUrlInput = document.getElementById('sandbox-url');
  const sandboxModeSelect = document.getElementById('sandbox-mode');
  const sandboxKeyInput = document.getElementById('sandbox-key');
  const sandboxHostInput = document.getElementById('sandbox-host');
  const sandboxWaitCheck = document.getElementById('sandbox-wait');

  const snippetCurl = document.getElementById('snippet-curl');
  const snippetPython = document.getElementById('snippet-python');
  const snippetJs = document.getElementById('snippet-js');

  function updateSandboxSnippets() {
    if (!snippetCurl || !snippetPython || !snippetJs) return;

    const url = sandboxUrlInput?.value.trim() || 'https://1024terabox.com/s/1Ay4FfmgooobETTVRHcf4mA';
    const mode = sandboxModeSelect?.value || 'download';
    const key = sandboxKeyInput?.value.trim() || 'my_secret_key';
    const host = sandboxHostInput?.value.trim() || 'http://127.0.0.1:5000';
    const wait = sandboxWaitCheck?.checked ? '&wait=true' : '';

    // 1. cURL Snippet
    snippetCurl.innerHTML = `<span class="tok-cmd">curl</span> <span class="tok-opt">-X</span> GET \\\n  <span class="tok-opt">-H</span> <span class="tok-str">"X-API-Key: ${key}"</span> \\\n  <span class="tok-str">"${host}/api/resolve?url=${encodeURIComponent(url)}&mode=${mode}${wait}"</span>`;

    // 2. Python (httpx) Snippet
    snippetPython.innerHTML = `<span class="tok-cmd">import</span> httpx\n\nheaders = {<span class="tok-str">"X-API-Key"</span>: <span class="tok-str">"${key}"</span>}\nparams = {\n    <span class="tok-str">"url"</span>: <span class="tok-str">"${url}"</span>,\n    <span class="tok-str">"mode"</span>: <span class="tok-str">"${mode}"</span>${sandboxWaitCheck?.checked ? ',\n    "wait": "true"' : ''}\n}\n\nwith httpx.Client(timeout=30.0) as client:\n    response = client.get(<span class="tok-str">"${host}/api/resolve"</span>, params=params, headers=headers)\n    print(response.json())`;

    // 3. JavaScript (fetch) Snippet
    snippetJs.innerHTML = `<span class="tok-cmd">const</span> res = <span class="tok-cmd">await</span> fetch(\n  <span class="tok-str">\`${host}/api/resolve?url=\${encodeURIComponent("${url}")}&mode=${mode}${wait}\`</span>,\n  {\n    headers: { <span class="tok-str">'X-API-Key'</span>: <span class="tok-str">'${key}'</span> }\n  }\n);\n<span class="tok-cmd">const</span> data = <span class="tok-cmd">await</span> res.json();\nconsole.log(data);`;
  }

  [sandboxUrlInput, sandboxModeSelect, sandboxKeyInput, sandboxHostInput, sandboxWaitCheck].forEach((el) => {
    if (el) {
      el.addEventListener('input', updateSandboxSnippets);
      el.addEventListener('change', updateSandboxSnippets);
    }
  });

  updateSandboxSnippets();

  // 7. Command Palette / Search Modal (Ctrl+K / Cmd+K / /)
  const searchModal = document.getElementById('search-modal');
  const searchInput = document.getElementById('search-modal-input');
  const searchTriggers = document.querySelectorAll('.search-trigger');
  const searchResults = document.getElementById('search-modal-results');

  const searchableIndex = [
    { title: 'Overview & Architecture', cat: 'Getting Started', id: 'overview' },
    { title: 'Quick Start (30 Seconds)', cat: 'Getting Started', id: 'quickstart' },
    { title: 'Interactive API Sandbox', cat: 'Developer Tools', id: 'interactive-sandbox' },
    { title: 'Authentication & Headers', cat: 'Security', id: 'authentication' },
    { title: 'GET /api/resolve', cat: 'Endpoints', id: 'ep-resolve' },
    { title: 'GET /api/stream/manifest', cat: 'Endpoints', id: 'ep-manifest' },
    { title: 'GET /api/stream/segment', cat: 'Endpoints', id: 'ep-segment' },
    { title: 'GET /api/download', cat: 'Endpoints', id: 'ep-download' },
    { title: 'GET /api/thumbnail', cat: 'Endpoints', id: 'ep-thumbnail' },
    { title: 'GET /api/stats', cat: 'Endpoints', id: 'ep-stats' },
    { title: 'POST /api/admin/config', cat: 'Admin', id: 'ep-admin' },
    { title: 'GET /api/cron/validate', cat: 'Admin', id: 'ep-cron' },
    { title: 'Environment Variables Specification', cat: 'Configuration', id: 'environment-variables' },
    { title: 'HMAC URL Signing & TTLs', cat: 'Security', id: 'url-signing' },
    { title: 'Deploy to Railway', cat: 'Deployment', id: 'deploy-railway' },
    { title: 'Deploy to Render', cat: 'Deployment', id: 'deploy-render' },
    { title: 'Deploy to Vercel', cat: 'Deployment', id: 'deploy-vercel' },
    { title: 'Docker Multi-Stage Serving', cat: 'Deployment', id: 'deploy-docker' },
    { title: 'Load Testing & Benchmarks', cat: 'Performance', id: 'benchmarking' }
  ];

  function openSearchModal() {
    if (!searchModal) return;
    searchModal.classList.add('open');
    searchInput?.focus();
    renderSearchResults('');
  }

  function closeSearchModal() {
    if (!searchModal) return;
    searchModal.classList.remove('open');
    if (searchInput) searchInput.value = '';
  }

  function renderSearchResults(query) {
    if (!searchResults) return;
    const cleanQuery = query.toLowerCase().trim();
    const filtered = cleanQuery
      ? searchableIndex.filter((item) => item.title.toLowerCase().includes(cleanQuery) || item.cat.toLowerCase().includes(cleanQuery))
      : searchableIndex.slice(0, 8);

    if (!filtered.length) {
      searchResults.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.9rem;">No matching documentation found.</div>`;
      return;
    }

    searchResults.innerHTML = filtered
      .map(
        (item) => `
        <div class="search-result-item" data-id="${item.id}">
          <span class="search-result-title">${item.title}</span>
          <span class="search-result-cat">${item.cat}</span>
        </div>
      `
      )
      .join('');

    searchResults.querySelectorAll('.search-result-item').forEach((item) => {
      item.addEventListener('click', () => {
        const id = item.dataset.id;
        closeSearchModal();
        const targetEl = document.getElementById(id);
        if (targetEl) {
          targetEl.scrollIntoView({ behavior: 'smooth' });
        }
      });
    });
  }

  searchTriggers.forEach((trigger) => {
    trigger.addEventListener('click', openSearchModal);
  });

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      renderSearchResults(e.target.value);
    });
  }

  // Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      if (searchModal?.classList.contains('open')) {
        closeSearchModal();
      } else {
        openSearchModal();
      }
    } else if (e.key === 'Escape' && searchModal?.classList.contains('open')) {
      closeSearchModal();
    } else if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
      e.preventDefault();
      openSearchModal();
    }
  });

  if (searchModal) {
    searchModal.addEventListener('click', (e) => {
      if (e.target === searchModal) {
        closeSearchModal();
      }
    });
  }
})();
