// --- CSP DSB - Popup ---
// Full control panel: toggle, rules CRUD, CSP auto-detect, export/import, preferences.

// --- Alert ---
function alert_msg(msg, type) {
  var id = 'alert-overlay';
  var e = document.getElementById(id);
  if (!e) { e = document.createElement('div'); e.id = id; document.body.appendChild(e); }
  var m = document.createElement('div');
  var bg = type === 'success' ? 'var(--success-bg)' : 'var(--warning-bg)';
  var border = type === 'success' ? 'var(--success)' : 'var(--warning)';
  var color = type === 'success' ? 'var(--success)' : 'var(--text)';
  m.style.cssText = 'background:' + bg + ';color:' + color + ';border:1px solid ' + border + ';' +
    'border-radius:var(--radius);padding:8px 16px;margin-bottom:6px;max-width:460px;' +
    'font-size:12px;font-weight:600;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.15);';
  m.textContent = msg;
  m.addEventListener('click', function() { m.remove(); });
  e.appendChild(m);
  setTimeout(function() { if (m.parentNode) m.remove(); }, 3000);
}

// --- Log ---
var logCleared = false;

function clearLog() {
  var logEl = document.getElementById('log');
  if (logEl) logEl.innerHTML = '';
  logCleared = true;
}

function popupLog(s) {
  var logEl = document.getElementById('log');
  if (!logEl) return;
  if (!logCleared) { logEl.innerHTML = ''; logCleared = true; }
  var text = (s || '').replace(/\s+$/, '');
  if (!text) return;

  text.split('\n').forEach(function(line) {
    var entry = document.createElement('div');
    entry.className = 'log-entry';
    if (/^error/i.test(line)) entry.classList.add('log-error');
    else if (/^warning/i.test(line)) entry.classList.add('log-warning');
    else if (/saved/i.test(line) || /success/i.test(line)) entry.classList.add('log-success');
    else if (/rule/i.test(line)) entry.classList.add('log-info');
    entry.textContent = line;
    logEl.insertBefore(entry, logEl.firstChild);
  });
}

// --- State ---
var g_rules = [];
var g_enabled = false;
var g_currentTabUrl = null;
var g_currentTabHost = null;
var g_rawMode = {};  // per-rule: g_rawMode[ruleId] === true means raw text mode
var g_collapsed = {};  // per-rule: g_collapsed[ruleId] !== false means collapsed (default true)

// --- CSP Directive Utilities ---

// Well-known CSP directives for the add-directive dropdown
var KNOWN_DIRECTIVES = [
  'default-src', 'script-src', 'style-src', 'img-src', 'connect-src',
  'font-src', 'object-src', 'media-src', 'frame-src', 'child-src',
  'form-action', 'frame-ancestors', 'base-uri', 'manifest-src', 'worker-src',
  'upgrade-insecure-requests', 'block-all-mixed-content', 'report-uri', 'report-to'
];

// Parse a CSP policy string into an array of {name, value} directives.
// Preserves original value formatting as much as possible.
function parseCspToDirectives(cspStr) {
  if (!cspStr) return [];
  // Handle 'no-csp' special case
  if (/^\s*no-csp\s*$/i.test(cspStr)) {
    return [{ name: 'no-csp', value: '' }];
  }
  var directives = [];
  var parts = cspStr.split(';');
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i].trim();
    if (!part) continue;
    // Split on first whitespace: directive-name rest...
    var spaceIdx = -1;
    for (var j = 0; j < part.length; j++) {
      if (part[j] === ' ' || part[j] === '\t') { spaceIdx = j; break; }
    }
    if (spaceIdx > 0) {
      // Collapse all whitespace (newlines, tabs, multi-spaces) to single spaces
      // so the full value displays in one line inside the <input>
      var rawValue = part.substring(spaceIdx + 1).replace(/\s+/g, ' ').trim();
      directives.push({
        name: part.substring(0, spaceIdx).toLowerCase(),
        value: rawValue
      });
    } else {
      // Flag directives like 'upgrade-insecure-requests' have no value
      directives.push({ name: part.toLowerCase(), value: '' });
    }
  }
  return directives;
}

// Reassemble a directives array back into a CSP policy string.
function directivesToCspString(directives) {
  if (!directives || directives.length === 0) return '';
  var parts = [];
  for (var i = 0; i < directives.length; i++) {
    var d = directives[i];
    if (d.name === 'no-csp') return 'no-csp';
    if (d.value) {
      parts.push(d.name + ' ' + d.value);
    } else {
      parts.push(d.name);
    }
  }
  return parts.join('; ');
}

// Get available directives not yet in the given list (for the add dropdown)
function availableDirectives(existingNames) {
  var result = [];
  for (var i = 0; i < KNOWN_DIRECTIVES.length; i++) {
    if (existingNames.indexOf(KNOWN_DIRECTIVES[i]) < 0) {
      result.push(KNOWN_DIRECTIVES[i]);
    }
  }
  return result;
}

// --- Status Bar ---
function updateStatusBar() {
  var bar = document.getElementById('status-bar');
  if (g_enabled) {
    var activeCount = g_rules.filter(function(r) { return r.enabled; }).length;
    bar.textContent = 'Active - ' + activeCount + ' rule(s) modifying CSP headers';
    bar.className = 'status-bar active';
  } else {
    bar.textContent = 'Inactive - Master switch is OFF';
    bar.className = 'status-bar inactive';
  }
}

// --- Render Rules ---
function renderRules() {
  var list = document.getElementById('ruleList');
  var empty = document.getElementById('emptyState');
  var summary = document.getElementById('ruleSummary');

  list.innerHTML = '';

  if (g_rules.length === 0) {
    empty.style.display = '';
    summary.textContent = '0 rules';
    updateStatusBar();
    return;
  }

  empty.style.display = 'none';
  var activeCount = 0;
  for (var r = 0; r < g_rules.length; r++) {
    if (g_rules[r].enabled) activeCount++;
  }
  var draftCount = 0;
  for (var dr = 0; dr < g_rules.length; dr++) {
    if (g_rules[dr]._draft) draftCount++;
  }
  summary.textContent = g_rules.length + ' rule(s), ' + activeCount + ' active' +
    (draftCount > 0 ? ', ' + draftCount + ' unsaved' : '');
  updateStatusBar();

  g_rules.forEach(function(rule, idx) {
    var isCollapsed = g_collapsed[rule.id] !== false; // default collapsed for existing rules

    var card = document.createElement('div');
    card.className = 'rule-card' + (rule.enabled ? '' : ' rule-disabled') +
      (rule._draft ? ' rule-draft' : '');
    card.dataset.ruleId = rule.id;

    // --- Header: index + url + collapse toggle + actions ---
    var header = document.createElement('div');
    header.className = 'rule-header';

    var indexEl = document.createElement('span');
    indexEl.className = 'rule-index';
    indexEl.textContent = '#' + (idx + 1);

    // Draft badge
    if (rule._draft) {
      var draftBadge = document.createElement('span');
      draftBadge.className = 'draft-badge';
      draftBadge.textContent = 'unsaved';
      header.appendChild(indexEl);
      header.appendChild(draftBadge);
    } else {
      header.appendChild(indexEl);
    }

    var urlInput = document.createElement('input');
    urlInput.type = 'text';
    urlInput.className = 'rule-url-input';
    urlInput.value = rule.url || '';
    urlInput.placeholder = 'https://example.com/*';
    urlInput.spellcheck = false;
    urlInput.addEventListener('input', function() {
      rule.url = urlInput.value;
    });

    var actions = document.createElement('div');
    actions.className = 'rule-actions';

    // Collapse/Expand toggle
    var collapseBtn = document.createElement('button');
    collapseBtn.className = 'btn-icon btn-collapse';
    collapseBtn.innerHTML = isCollapsed ? '▶' : '▼';
    collapseBtn.title = isCollapsed ? 'Expand rule' : 'Collapse rule';
    collapseBtn.addEventListener('click', function() {
      g_collapsed[rule.id] = !isCollapsed;
      renderRules();
    });

    // Move up
    var upBtn = document.createElement('button');
    upBtn.className = 'btn-icon btn-move';
    upBtn.innerHTML = '▲';
    upBtn.title = 'Move up';
    upBtn.disabled = idx === 0;
    upBtn.addEventListener('click', function() { moveRule(rule.id, -1); });

    // Move down
    var downBtn = document.createElement('button');
    downBtn.className = 'btn-icon btn-move';
    downBtn.innerHTML = '▼';
    downBtn.title = 'Move down';
    downBtn.disabled = idx === g_rules.length - 1;
    downBtn.addEventListener('click', function() { moveRule(rule.id, 1); });

    // Per-rule toggle
    var toggleBtn = document.createElement('button');
    toggleBtn.className = 'btn-icon ' + (rule.enabled ? 'btn-toggle-on' : 'btn-toggle-off');
    toggleBtn.innerHTML = rule.enabled ? '◉' : '○';
    toggleBtn.title = rule.enabled ? 'Disable rule' : 'Enable rule';
    toggleBtn.addEventListener('click', function() {
      toggleSingleRule(rule.id);
    });

    // Delete
    var delBtn = document.createElement('button');
    delBtn.className = 'btn-icon btn-delete';
    delBtn.innerHTML = '✕';
    delBtn.title = 'Delete rule';
    delBtn.addEventListener('click', function() {
      var label = rule.url || 'this rule';
      if (rule._draft) label = 'this unsaved draft';
      if (confirm('Delete rule for ' + label + '?')) {
        deleteRuleItem(rule.id);
      }
    });

    actions.appendChild(collapseBtn);
    actions.appendChild(upBtn);
    actions.appendChild(downBtn);
    actions.appendChild(toggleBtn);
    actions.appendChild(delBtn);

    header.appendChild(urlInput);
    header.appendChild(actions);
    card.appendChild(header);

    // --- Collapsible body: policy + toggle link ---
    var body = document.createElement('div');
    body.className = 'rule-body' + (isCollapsed ? ' rule-body-collapsed' : '');

    // Formatting hint
    var formatHint = document.createElement('div');
    formatHint.className = 'format-hint';
    formatHint.textContent = 'Note: Multiple values must be separated by spaces (e.g. \'self\' https://example.com ws://localhost:8080)';
    body.appendChild(formatHint);

    // --- Policy section: structured directives or raw textarea ---
    var policySection = document.createElement('div');
    policySection.className = 'policy-section';

    if (g_rawMode[rule.id]) {
      // --- Raw textarea mode ---
      var rawArea = document.createElement('textarea');
      rawArea.className = 'rule-policy-input';
      rawArea.value = rule.policy || '';
      rawArea.placeholder = 'Enter the COMPLETE CSP policy to REPLACE the existing header';
      rawArea.rows = 4;
      rawArea.spellcheck = false;
      rawArea.addEventListener('input', function() {
        rule.policy = rawArea.value;
      });
      policySection.appendChild(rawArea);
    } else {
      // --- Structured directive rows ---
      var dirList = document.createElement('div');
      dirList.className = 'directive-list';

      var directives = parseCspToDirectives(rule.policy || '');
      var existingNames = [];
      for (var di = 0; di < directives.length; di++) {
        existingNames.push(directives[di].name);
      }

      for (var d2 = 0; d2 < directives.length; d2++) {
        dirList.appendChild(buildDirectiveRow(rule, directives[d2], dirList));
      }

      // Add-directive row
      var avail = availableDirectives(existingNames);
      if (avail.length > 0) {
        var addRow = document.createElement('div');
        addRow.className = 'directive-add-row';

        var select = document.createElement('select');
        select.className = 'directive-add-select';
        for (var ai = 0; ai < avail.length; ai++) {
          var opt = document.createElement('option');
          opt.value = avail[ai];
          opt.textContent = avail[ai];
          select.appendChild(opt);
        }

        var addBtn = document.createElement('button');
        addBtn.className = 'btn-icon directive-add-btn';
        addBtn.innerHTML = '+';
        addBtn.title = 'Add directive';
        addBtn.addEventListener('click', function() {
          var newDir = { name: select.value, value: '' };
          directives.push(newDir);
          existingNames.push(newDir.name);
          // Insert new row before the add-row
          var newRow = buildDirectiveRow(rule, newDir, dirList);
          dirList.insertBefore(newRow, addRow);
          // Rebuild available directives dropdown
          var updatedAvail = availableDirectives(existingNames);
          select.innerHTML = '';
          if (updatedAvail.length === 0) {
            addRow.style.display = 'none';
          } else {
            for (var ua = 0; ua < updatedAvail.length; ua++) {
              var updOpt = document.createElement('option');
              updOpt.value = updatedAvail[ua];
              updOpt.textContent = updatedAvail[ua];
              select.appendChild(updOpt);
            }
          }
          updateRulePolicyFromDirectives(rule, dirList);
        });

        addRow.appendChild(select);
        addRow.appendChild(addBtn);
        dirList.appendChild(addRow);
      }

      policySection.appendChild(dirList);
    }

    body.appendChild(policySection);

    // --- Toggle raw/structured link ---
    var toggleLink = document.createElement('button');
    toggleLink.className = 'toggle-raw-link';
    toggleLink.textContent = g_rawMode[rule.id] ? 'Structured view' : 'Edit raw CSP';
    toggleLink.addEventListener('click', function() {
      if (g_rawMode[rule.id]) {
        // Switching from raw to structured: save textarea value first
        var ta = card.querySelector('.rule-policy-input');
        if (ta) rule.policy = ta.value;
        g_rawMode[rule.id] = false;
      } else {
        // Switching from structured to raw: policy is already in sync
        g_rawMode[rule.id] = true;
      }
      renderRules();
    });
    body.appendChild(toggleLink);

    // no-csp hint — placed below the raw/structured toggle for visibility
    var noCspHint = document.createElement('div');
    noCspHint.className = 'format-hint no-csp-hint';
    noCspHint.textContent = 'Tip: Switch to "Edit raw CSP" mode, then type ONLY "no-csp" to remove ALL CSP headers from this site.';
    body.appendChild(noCspHint);

    card.appendChild(body);

    // --- Footer: status + apply ---
    var footer = document.createElement('div');
    footer.className = 'rule-footer';

    var status = document.createElement('span');
    status.className = 'rule-status ' + (rule.enabled ? 'status-active' : 'status-inactive');
    status.textContent = rule.enabled ? 'Enabled' : 'Disabled';
    if (rule._draft) status.textContent = 'Unsaved';

    var applyBtn = document.createElement('button');
    applyBtn.className = 'rule-apply-btn';
    applyBtn.textContent = rule._draft ? 'Save & Apply' : 'Replace & Apply';
    applyBtn.addEventListener('click', function() {
      applySingleRule(rule);
    });

    footer.appendChild(status);
    footer.appendChild(applyBtn);

    card.appendChild(footer);
    list.appendChild(card);
  });
}

// --- Directive Row Builder ---

// Build a single directive row: [name] [input value] [×]
function buildDirectiveRow(rule, dir, dirList) {
  var row = document.createElement('div');
  row.className = 'directive-row';

  var nameLabel = document.createElement('span');
  nameLabel.className = 'directive-name';
  nameLabel.textContent = dir.name;
  nameLabel.title = dir.name;

  var valInput = document.createElement('input');
  valInput.type = 'text';
  valInput.className = 'directive-input';
  valInput.value = dir.value;
  valInput.title = dir.value;
  valInput.placeholder = 'sources...';
  valInput.spellcheck = false;
  valInput.addEventListener('input', function() {
    dir.value = valInput.value;
    valInput.title = valInput.value;
    updateRulePolicyFromDirectives(rule, dirList);
  });

  var delBtn = document.createElement('button');
  delBtn.className = 'btn-icon directive-del-btn';
  delBtn.innerHTML = '×';
  delBtn.title = 'Remove ' + dir.name;
  delBtn.addEventListener('click', function() {
    row.remove();
    // Refresh add-dropdown if this was the last of its kind
    updateRulePolicyFromDirectives(rule, dirList);
    // Re-render this card to refresh the add-directive dropdown
    renderRules();
  });

  row.appendChild(nameLabel);
  row.appendChild(valInput);
  row.appendChild(delBtn);
  return row;
}

// Collect directive values from the DOM and update rule.policy
function updateRulePolicyFromDirectives(rule, dirList) {
  var rows = dirList.querySelectorAll('.directive-row');
  var directives = [];
  for (var ri = 0; ri < rows.length; ri++) {
    var row = rows[ri];
    var nameEl = row.querySelector('.directive-name');
    var valEl = row.querySelector('.directive-input');
    if (nameEl && valEl) {
      directives.push({ name: nameEl.textContent, value: valEl.value.trim() });
    }
  }
  rule.policy = directivesToCspString(directives);
}

// --- Rule Operations ---

// Flash the apply button text briefly (e.g. "✓ Applied!")
function flashApplyBtn(ruleId, text) {
  var card = document.querySelector('.rule-card[data-rule-id="' + ruleId + '"]');
  if (!card) return;
  var btn = card.querySelector('.rule-apply-btn');
  if (!btn) return;
  var origText = btn.textContent;
  btn.textContent = text;
  btn.style.color = 'var(--success)';
  btn.style.borderColor = 'var(--success)';
  btn.style.background = 'var(--success-bg)';
  btn.disabled = true;
  setTimeout(function() {
    btn.textContent = origText;
    btn.style.color = '';
    btn.style.borderColor = '';
    btn.style.background = '';
    btn.disabled = false;
  }, 2000);
}

function applySingleRule(rule) {
  // If in structured mode, collect latest values from DOM first
  if (!g_rawMode[rule.id]) {
    var card = document.querySelector('.rule-card[data-rule-id="' + rule.id + '"]');
    if (card) {
      var dirList = card.querySelector('.directive-list');
      if (dirList) {
        updateRulePolicyFromDirectives(rule, dirList);
      }
    }
  }

  if (!rule.url || !rule.policy) {
    alert_msg('URL and policy are required');
    return;
  }
  var ro = cspParse(rule.policy.trim());
  if (ro.error) {
    alert_msg(ro.error);
    return;
  }

  if (rule._draft) {
    // New draft rule: send addRule to service worker to persist
    chrome.runtime.sendMessage({
      type: 'addRule',
      rule: { url: rule.url, policy: rule.policy, enabled: rule.enabled }
    }, function(resp) {
      if (chrome.runtime.lastError) { alert_msg(chrome.runtime.lastError.message); return; }
      if (resp && resp.error) { alert_msg(resp.error); return; }
      if (resp && resp.rule) {
        // Replace draft with persisted rule
        var oldId = rule.id;
        for (var i = 0; i < g_rules.length; i++) {
          if (g_rules[i].id === oldId) { g_rules[i] = resp.rule; break; }
        }
        // Migrate state from draft ID to real ID
        if (g_rawMode[oldId] !== undefined) {
          g_rawMode[resp.rule.id] = g_rawMode[oldId];
          delete g_rawMode[oldId];
        }
        if (g_collapsed[oldId] !== undefined) {
          g_collapsed[resp.rule.id] = g_collapsed[oldId];
          delete g_collapsed[oldId];
        }
        renderRules();
        flashApplyBtn(resp.rule.id, '✓ Applied!');
      }
    });
  } else {
    // Existing rule: send updateRule
    chrome.runtime.sendMessage({ type: 'updateRule', ruleId: rule.id, rule: rule }, function(resp) {
      if (chrome.runtime.lastError) { alert_msg(chrome.runtime.lastError.message); return; }
      if (resp && resp.error) { alert_msg(resp.error); return; }
      flashApplyBtn(rule.id, '✓ Applied!');
    });
  }
}

function deleteRuleItem(ruleId) {
  // Check if it's a draft (not yet saved)
  var rule = null;
  for (var i = 0; i < g_rules.length; i++) {
    if (g_rules[i].id === ruleId) { rule = g_rules[i]; break; }
  }
  if (rule && rule._draft) {
    // Draft rule: just remove from local array, no service worker call needed
    g_rules = g_rules.filter(function(r) { return r.id !== ruleId; });
    delete g_rawMode[ruleId];
    delete g_collapsed[ruleId];
    renderRules();
    popupLog('Draft discarded');
    return;
  }

  chrome.runtime.sendMessage({ type: 'deleteRule', ruleId: ruleId }, function(resp) {
    if (chrome.runtime.lastError) { popupLog('error: ' + chrome.runtime.lastError.message); return; }
    if (resp && resp.error) { popupLog('error: ' + resp.error); return; }
    g_rules = g_rules.filter(function(r) { return r.id !== ruleId; });
    delete g_rawMode[ruleId];
    delete g_collapsed[ruleId];
    renderRules();
    popupLog('Rule deleted');
  });
}

function toggleSingleRule(ruleId) {
  // Check if it's a draft
  var rule = null;
  var idx = -1;
  for (var i = 0; i < g_rules.length; i++) {
    if (g_rules[i].id === ruleId) { rule = g_rules[i]; idx = i; break; }
  }
  if (rule && rule._draft) {
    // Draft: toggle locally only
    rule.enabled = !rule.enabled;
    renderRules();
    popupLog('Draft ' + (rule.enabled ? 'enabled' : 'disabled'));
    return;
  }

  chrome.runtime.sendMessage({ type: 'toggleRule', ruleId: ruleId }, function(resp) {
    if (chrome.runtime.lastError) { popupLog('error: ' + chrome.runtime.lastError.message); return; }
    if (resp && resp.error) { popupLog('error: ' + resp.error); return; }
    if (resp && resp.rule) {
      var idx2 = -1;
      for (var j = 0; j < g_rules.length; j++) {
        if (g_rules[j].id === ruleId) { idx2 = j; break; }
      }
      if (idx2 >= 0) {
        g_rules[idx2] = resp.rule;
        renderRules();
        popupLog('Rule ' + (resp.rule.enabled ? 'enabled' : 'disabled') + ': ' + resp.rule.url);
      }
    }
  });
}

function moveRule(ruleId, direction) {
  // Check if it's a draft
  var rule = null;
  var idx = -1;
  for (var i = 0; i < g_rules.length; i++) {
    if (g_rules[i].id === ruleId) { rule = g_rules[i]; idx = i; break; }
  }
  if (rule && rule._draft) {
    // Draft: reorder locally only
    var newIdx = idx + direction;
    if (newIdx < 0 || newIdx >= g_rules.length) return;
    var tmp = g_rules[idx];
    g_rules[idx] = g_rules[newIdx];
    g_rules[newIdx] = tmp;
    renderRules();
    return;
  }

  chrome.runtime.sendMessage({ type: 'moveRule', ruleId: ruleId, direction: direction }, function(resp) {
    if (chrome.runtime.lastError) { popupLog('error: ' + chrome.runtime.lastError.message); return; }
    if (resp && resp.error) { popupLog('error: ' + resp.error); return; }
    if (resp && resp.rules) {
      g_rules = resp.rules;
      renderRules();
    }
  });
}

// --- Global Toggle ---
function globalToggle() {
  chrome.runtime.sendMessage({ type: 'toggle' }, function(resp) {
    if (chrome.runtime.lastError) { popupLog('error: ' + chrome.runtime.lastError.message); return; }
    if (resp && typeof resp.enabled !== 'undefined') {
      g_enabled = resp.enabled;
      document.getElementById('enable-toggle').checked = g_enabled;
      renderRules();
      updateStatusBar();
      popupLog(g_enabled ? 'Global: Enabled' : 'Global: Disabled');
    }
  });
}

// --- CSP Auto-Detect ---

// Convert a full URL to a match pattern (e.g., https://example.com/page -> https://example.com/*)
function urlToMatchPattern(url) {
  if (!url) return '';
  try {
    // Use a simple approach to extract origin
    var m = url.match(/^(https?:\/\/[^\/]+)/);
    if (m) {
      return m[1] + '/*';
    }
  } catch (e) { /* ignore */ }
  return url + '*';
}

// Get current active tab info
function getCurrentTab(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
      callback(null);
      return;
    }
    var tab = tabs[0];
    var url = tab.url || '';
    // Only process http/https URLs
    if (url.indexOf('http://') !== 0 && url.indexOf('https://') !== 0) {
      callback(null);
      return;
    }
    callback({ url: url, title: tab.title || '', id: tab.id });
  });
}

// Fetch CSP headers from the current tab's URL via service worker
function fetchCspForTab(tabUrl, callback) {
  chrome.runtime.sendMessage({ type: 'fetchCsp', url: tabUrl }, function(resp) {
    if (chrome.runtime.lastError) {
      callback(null, chrome.runtime.lastError.message);
      return;
    }
    if (resp && resp.error) {
      callback(null, resp.error);
      return;
    }
    callback(resp && resp.csp ? resp.csp : null, null);
  });
}

// Create a local draft rule (NOT saved to storage yet — only saved when "Replace & Apply" is clicked)
function createDraftRule(url, policy) {
  var draft = {
    id: 'draft_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8),
    url: url || '',
    policy: policy || '',
    enabled: true,
    _draft: true
  };
  g_rules.push(draft);
  // Drafts always start in expanded (non-collapsed) mode so user can edit
  g_collapsed[draft.id] = false;
  g_rawMode[draft.id] = false;
  renderRules();
}

// Add rule - auto-fills URL + CSP from current site, falls back to empty rule
function addRule() {
  if (!g_currentTabUrl) {
    // No current tab detected (e.g., chrome:// page) - create empty draft rule
    createDraftRule('', '');
    return;
  }

  var matchPattern = urlToMatchPattern(g_currentTabUrl);

  // Show loading indicator
  var btn = document.getElementById('addRuleBtn');
  var origText = btn.textContent;
  btn.textContent = 'Detecting CSP...';
  btn.disabled = true;

  fetchCspForTab(g_currentTabUrl, function(cspValue, error) {
    btn.textContent = origText;
    btn.disabled = false;

    if (error) {
      popupLog('warning: Could not fetch CSP header: ' + error);
    }

    if (cspValue) {
      popupLog('CSP header detected for ' + g_currentTabHost);
    } else if (!error) {
      popupLog('No CSP header found on ' + g_currentTabHost);
    }

    createDraftRule(matchPattern, cspValue || '');
  });
}

// --- Export / Import ---
function exportRules() {
  var man = chrome.runtime.getManifest();
  var data = {
    app: man.name + ' v' + man.version,
    exportedAt: new Date().toISOString(),
    rules: g_rules
  };
  var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'csp-dsb-rules-' + formatDate() + '.json';
  a.click();
  URL.revokeObjectURL(url);
  popupLog('Rules exported (' + g_rules.length + ' rules)');
}

function importRules() {
  var input = document.createElement('input');
  input.type = 'file';
  input.accept = 'application/json,.json';
  input.addEventListener('change', function() {
    var file = input.files && input.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.addEventListener('load', function() {
      try {
        var data = JSON.parse(reader.result);
        if (!data || !data.rules || !Array.isArray(data.rules)) {
          throw new Error('Invalid file format: rules array not found');
        }
        for (var i = 0; i < data.rules.length; i++) {
          var r = data.rules[i];
          if (!r.url || !r.policy) {
            throw new Error('Rule #' + (i+1) + ' is missing url or policy');
          }
          r.id = generateRuleId();
        }
        chrome.runtime.sendMessage({ type: 'replaceAllRules', rules: data.rules }, function(resp) {
          if (chrome.runtime.lastError) { popupLog('error: ' + chrome.runtime.lastError.message); return; }
          if (resp && resp.error) { popupLog('error: ' + resp.error); return; }
          if (resp && resp.rules) {
            g_rules = resp.rules;
            renderRules();
            popupLog('Imported ' + g_rules.length + ' rule(s) from ' + file.name);
          }
        });
      } catch (e) {
        var msg = e.name + ': ' + e.message;
        popupLog(msg);
        alert_msg(msg);
      }
    });
    reader.readAsText(file);
  });
  input.click();
}

function formatDate() {
  var d = new Date();
  var f = function(n) { return ('0' + n).slice(-2); };
  return d.getFullYear() + f(d.getMonth() + 1) + f(d.getDate()) +
    '-' + f(d.getHours()) + f(d.getMinutes()) + f(d.getSeconds());
}

// --- Message Listener ---
chrome.runtime.onMessage.addListener(function(m) {
  if (m.type === 'log') { popupLog(m.str); }
  else if (m.type === 'statusChange') {
    g_enabled = m.enabled;
    document.getElementById('enable-toggle').checked = g_enabled;
    renderRules();
    updateStatusBar();
  }
});

// --- Init ---
document.addEventListener('DOMContentLoaded', function() {
  var toggle = document.getElementById('enable-toggle');
  var g_initializing = true;  // suppress change event while restoring saved state

  // Load full settings
  chrome.runtime.sendMessage({ type: 'getAllSettings' }, function(v) {
    if (chrome.runtime.lastError) {
      document.getElementById('status-bar').textContent = 'Error loading settings';
      toggle.disabled = true;
      return;
    }
    if (!v || v.error) {
      document.getElementById('status-bar').textContent = 'Error: ' + (v && v.error);
      return;
    }

    // State
    g_rules = v.rules || [];
    g_enabled = v.enabled === true;

    // UI — set checked while flag suppresses the change handler
    toggle.checked = g_enabled;
    g_initializing = false;
    renderRules();
    updateStatusBar();
  });

  // Detect current tab
  getCurrentTab(function(tab) {
    if (tab) {
      g_currentTabUrl = tab.url;
      g_currentTabHost = urlToMatchPattern(tab.url).replace('/*', '');
      var siteEl = document.getElementById('currentSite');
      var urlEl = document.getElementById('currentSiteUrl');
      siteEl.style.display = '';
      urlEl.textContent = g_currentTabHost;
    }
  });

  // Global toggle — skip programmatic changes during init
  toggle.addEventListener('change', function() {
    if (g_initializing) return;
    globalToggle();
  });

  // Add rule button
  document.getElementById('addRuleBtn').addEventListener('click', function() {
    addRule();
  });

  // Export/Import
  document.getElementById('exportBtn').addEventListener('click', exportRules);
  document.getElementById('importBtn').addEventListener('click', importRules);
});
