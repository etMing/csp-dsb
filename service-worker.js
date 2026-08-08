// --- CSP DSB --- Service Worker ---
// Manages declarativeNetRequest rules, multi-rule storage, state, and messaging.

importScripts('util.js');

// --- State ---

var enabled = false;           // global master toggle
var debug = false;
var noCache = false;
var rules = [];                // [{id, url, policy, enabled}, ...]
var activeRuleIds = [];        // currently registered DNR rule IDs
var g_initPromise = null;     // tracks in-flight init() promise to avoid concurrent runs

// --- Default Settings ---

var DEFAULT_SETTINGS = {
  enableAtStartup: false,
  printDebugInfo: false,
  colorScheme: 'auto'
  // Note: rules are stored in chrome.storage.local (not sync) due to size limits (sync = 8KB/item)
};

// --- Rule Management (DNR) ---

// Compare two DNR rule objects for equality (all fields).
function dnrRulesEqual(a, b) {
  if (a.id !== b.id) return false;
  if (a.priority !== b.priority) return false;
  // Compare action and condition by JSON — handles nested objects/arrays
  if (JSON.stringify(a.action) !== JSON.stringify(b.action)) return false;
  if (JSON.stringify(a.condition) !== JSON.stringify(b.condition)) return false;
  return true;
}

// Compute the diff between currently registered DNR rules and desired rules.
// Returns {toAdd: [], toRemove: []} — only changed rules are touched.
function computeDnrDiff(desiredRules, existingRules) {
  var existingMap = {};
  for (var i = 0; i < existingRules.length; i++) {
    existingMap[existingRules[i].id] = existingRules[i];
  }

  var desiredMap = {};
  for (var j = 0; j < desiredRules.length; j++) {
    desiredMap[desiredRules[j].id] = desiredRules[j];
  }

  var toAdd = [];
  var toRemove = [];

  // Find rules to add (new or changed)
  for (var k = 0; k < desiredRules.length; k++) {
    var desired = desiredRules[k];
    var existing = existingMap[desired.id];
    if (!existing) {
      toAdd.push(desired);
    } else if (!dnrRulesEqual(desired, existing)) {
      toRemove.push(desired.id);
      toAdd.push(desired);
    }
  }

  // Find rules to remove (no longer desired)
  for (var m = 0; m < existingRules.length; m++) {
    var exId = existingRules[m].id;
    if (!desiredMap[exId]) {
      toRemove.push(exId);
    }
  }

  return { toAdd: toAdd, toRemove: toRemove };
}

function clearAllRules() {
  console.log('[CSP DSB] clearAllRules() called');
  return chrome.declarativeNetRequest.getDynamicRules().then(function(existing) {
    console.log('[CSP DSB] clearAllRules: ' + existing.length + ' existing DNR rules');
    if (existing.length === 0) {
      activeRuleIds = [];
      return;
    }
    var ids = existing.map(function(r) { return r.id; });
    console.log('[CSP DSB] clearAllRules: removing ' + ids.length + ' rules: [' + ids.join(',') + ']');
    return chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ids }).then(function() {
      console.log('[CSP DSB] clearAllRules: done, all DNR rules removed');
      activeRuleIds = [];
    });
  }).catch(function(err) {
    console.error('[CSP DSB] clearAllRules error:', err);
  });
}

function registerRules(isStartup) {
  console.log('[CSP DSB] registerRules() called: enabled=' + enabled + ', rules.length=' + rules.length +
    ', isStartup=' + !!isStartup);

  // Only register rules that are both (a) individually enabled and (b) under global enable
  var effectiveRules = enabled ? rules.filter(function(r) { return r.enabled; }) : [];
  console.log('[CSP DSB] registerRules: effectiveRules=' + effectiveRules.length + ' (enabled=' + enabled +
    ', total=' + rules.length + ')');

  if (effectiveRules.length === 0) {
    // During startup: if storage returned empty but DNR rules exist, preserve them
    // (storage may not be ready yet on cold browser start).
    // During normal operation: trust the rules — clear DNR rules.
    if (isStartup) {
      return chrome.declarativeNetRequest.getDynamicRules().then(function(existing) {
        if (existing.length > 0) {
          console.warn('[CSP DSB] SAFETY: effectiveRules=0 on startup but ' + existing.length +
            ' DNR rules exist — PRESERVING (storage may not be ready).');
          activeRuleIds = existing.map(function(r) { return r.id; });
          return;
        }
        console.log('[CSP DSB] registerRules: no effective rules, no existing rules — nothing to do');
        activeRuleIds = [];
      });
    }
    // Normal operation: user intentionally cleared/disabled all rules
    console.log('[CSP DSB] registerRules: no effective rules — clearing all DNR rules');
    return clearAllRules();
  }

  var result = generateAllDnrRules(effectiveRules, noCache);
  var dnrRules = result.dnrRules;

  if (dnrRules.length === 0) {
    console.log('[CSP DSB] registerRules: generateAllDnrRules produced 0 DNR rules from ' +
      effectiveRules.length + ' user-rules');
    if (isStartup) {
      return chrome.declarativeNetRequest.getDynamicRules().then(function(existing) {
        if (existing.length > 0) {
          console.warn('[CSP DSB] SAFETY: dnrRules=0 on startup but ' + existing.length +
            ' DNR rules exist — PRESERVING.');
          activeRuleIds = existing.map(function(r) { return r.id; });
          return;
        }
        activeRuleIds = [];
      });
    }
    return clearAllRules();
  }

  console.log('[CSP DSB] registerRules: generated ' + dnrRules.length + ' DNR rules, checking against existing...');

  // Diff desired vs existing — only update what changed (avoids gap on restart)
  return chrome.declarativeNetRequest.getDynamicRules().then(function(existingRules) {
    console.log('[CSP DSB] registerRules: fetched ' + existingRules.length + ' existing DNR rules');
    var diff = computeDnrDiff(dnrRules, existingRules);

    if (diff.toAdd.length === 0 && diff.toRemove.length === 0) {
      // Rules are already up to date — no gap, no unnecessary update
      console.log('[CSP DSB] registerRules: DNR rules unchanged (' + dnrRules.length +
        ' active), skipping update');
      activeRuleIds = dnrRules.map(function(r) { return r.id; });
      return;
    }

    console.log('[CSP DSB] registerRules: diff +' + diff.toAdd.length + ' -' + diff.toRemove.length);
    if (diff.toRemove.length > 0) {
      console.log('[CSP DSB] registerRules: removing IDs [' + diff.toRemove.join(',') + ']');
    }

    return chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: diff.toRemove,
      addRules: diff.toAdd
    }).then(function() {
      activeRuleIds = dnrRules.map(function(r) { return r.id; });
      console.log('[CSP DSB] registerRules: DNR update SUCCESS, ' + activeRuleIds.length + ' rules active');
    }).catch(function(err) {
      console.error('[CSP DSB] registerRules: updateDynamicRules FAILED:', err);
      throw err;
    });
  }).catch(function(err) {
    console.error('[CSP DSB] registerRules error:', err);
    if (debug) log_message('Error: ' + err.message);
  });
}

// --- Icon ---

function updateIcon() {
  var iconName = enabled ? 'button-48-on' : 'button-48-off';
  try {
    chrome.action.setIcon({ path: { 48: 'icons/' + iconName + '.png' } });
    chrome.action.setTitle({ title: 'CSP DSB' });
  } catch (e) { /* ignore */ }
}

// --- Global Toggle ---

function toggleGlobal(state) {
  if (typeof state === 'boolean') {
    enabled = state;
  } else {
    enabled = !enabled;
  }

  updateIcon();

  return registerRules().then(function() {
    return chrome.storage.local.set({ enabled: enabled });
  }).then(function() {
    notifyUI('statusChange', { enabled: enabled });
  });
}

// --- Settings ---

function loadSettings() {
  console.log('[CSP DSB] loadSettings() started');
  return chrome.storage.sync.get(DEFAULT_SETTINGS).then(function(pref) {
    debug = pref.printDebugInfo || false;
    console.log('[CSP DSB] loadSettings: sync pref loaded, debug=' + debug);

    // Load rules from local storage (higher quota than sync)
    return chrome.storage.local.get(['rules']).then(function(localData) {
      console.log('[CSP DSB] loadSettings: local storage returned, rules type=' + typeof localData.rules +
        ', length=' + (localData.rules ? (typeof localData.rules === 'string' ? localData.rules.length : localData.rules.length) : 'null'));

      // Parse rules from JSON string
      try {
        if (typeof localData.rules === 'string' && localData.rules) {
          rules = JSON.parse(localData.rules);
          console.log('[CSP DSB] loadSettings: parsed ' + rules.length + ' rules from JSON string');
        } else if (Array.isArray(localData.rules)) {
          rules = localData.rules;
          console.log('[CSP DSB] loadSettings: loaded ' + rules.length + ' rules from array');
        } else {
          rules = [];
          console.log('[CSP DSB] loadSettings: no rules found in local storage (rules=[])');
        }
      } catch (e) {
        console.error('[CSP DSB] Failed to parse rules:', e);
        rules = [];
      }

      // Migration: if no rules in local, try loading from sync (old format)
      if (rules.length === 0) {
        try {
          if (typeof pref.rules === 'string' && pref.rules) {
            rules = JSON.parse(pref.rules);
            if (rules.length > 0) {
              console.log('[CSP DSB] Migrated ' + rules.length + ' rules from sync to local storage');
            }
          } else if (Array.isArray(pref.rules)) {
            rules = pref.rules;
            if (rules.length > 0) {
              console.log('[CSP DSB] Migrated ' + rules.length + ' rules from sync to local storage');
            }
          }
        } catch (e2) {
          console.error('[CSP DSB] Failed to parse migrated rules:', e2);
        }
      }

      // Ensure all rules have an id
      var changed = false;
      rules.forEach(function(rule) {
        if (!rule.id) {
          rule.id = generateRuleId();
          changed = true;
        }
      });

      console.log('[CSP DSB] loadSettings() complete: ' + rules.length + ' rules, changed=' + changed);
      return { pref: pref, changed: changed };
    });
  }).catch(function(err) {
    console.error('[CSP DSB] loadSettings() FAILED:', err);
    throw err;
  });
}

function saveRules() {
  return chrome.storage.local.set({ rules: JSON.stringify(rules) });
}

// --- CRUD Operations ---

function addRule(ruleData) {
  var rule = {
    id: generateRuleId(),
    url: (ruleData.url || '').trim(),
    policy: (ruleData.policy || '').trim(),
    enabled: ruleData.enabled !== false
  };

  // Don't validate at creation — allow empty drafts.
  // Validation happens in updateRule() when the user clicks Apply.

  rules.push(rule);
  return saveRules().then(function() {
    return registerRules();
  }).then(function() {
    return rule;
  });
}

function updateRule(ruleId, ruleData) {
  var idx = -1;
  for (var i = 0; i < rules.length; i++) {
    if (rules[i].id === ruleId) { idx = i; break; }
  }
  if (idx === -1) return Promise.reject(new Error('Rule not found: ' + ruleId));

  var updated = {
    id: ruleId,
    url: ruleData.url !== undefined ? (ruleData.url || '').trim() : rules[idx].url,
    policy: ruleData.policy !== undefined ? (ruleData.policy || '').trim() : rules[idx].policy,
    enabled: ruleData.enabled !== undefined ? ruleData.enabled : rules[idx].enabled
  };

  var err = validateRule(updated);
  if (err) return Promise.reject(new Error(err));

  rules[idx] = updated;
  return saveRules().then(function() {
    return registerRules();
  }).then(function() {
    return updated;
  });
}

function deleteRule(ruleId) {
  var idx = -1;
  for (var i = 0; i < rules.length; i++) {
    if (rules[i].id === ruleId) { idx = i; break; }
  }
  if (idx === -1) return Promise.reject(new Error('Rule not found: ' + ruleId));

  rules.splice(idx, 1);
  return saveRules().then(function() {
    return registerRules();
  });
}

function toggleRule(ruleId) {
  var idx = -1;
  for (var i = 0; i < rules.length; i++) {
    if (rules[i].id === ruleId) { idx = i; break; }
  }
  if (idx === -1) return Promise.reject(new Error('Rule not found: ' + ruleId));

  rules[idx].enabled = !rules[idx].enabled;
  return saveRules().then(function() {
    return registerRules();
  }).then(function() {
    return rules[idx];
  });
}

function moveRule(ruleId, direction) {
  var idx = -1;
  for (var i = 0; i < rules.length; i++) {
    if (rules[i].id === ruleId) { idx = i; break; }
  }
  if (idx === -1) return Promise.reject(new Error('Rule not found: ' + ruleId));

  var newIdx = idx + direction;
  if (newIdx < 0 || newIdx >= rules.length) {
    return Promise.resolve(rules); // already at edge
  }

  var tmp = rules[idx];
  rules[idx] = rules[newIdx];
  rules[newIdx] = tmp;

  return saveRules().then(function() {
    return registerRules();
  }).then(function() {
    return rules;
  });
}

// --- CSP Auto-Detection ---

// Fetch a URL and extract its CSP header value.
// Service workers in MV3 extensions have broad network access (not subject to page CORS).
function fetchCspFromUrl(url) {
  // Try HEAD first, fall back to GET with Range for minimal data transfer
  function tryHead() {
    return fetch(url, { method: 'HEAD', redirect: 'follow' }).then(function(resp) {
      return extractCspHeaders(resp);
    });
  }

  function tryGetRange() {
    return fetch(url, { headers: { 'Range': 'bytes=0-0' }, redirect: 'follow' }).then(function(resp) {
      return extractCspHeaders(resp);
    });
  }

  return tryHead().catch(function() {
    return tryGetRange();
  });
}

function extractCspHeaders(response) {
  // Check all known CSP header variants
  var cspHeaders = [
    'content-security-policy',
    'content-security-policy-report-only',
    'x-content-security-policy',
    'x-content-security-policy-report-only',
    'x-webkit-csp'
  ];
  for (var i = 0; i < cspHeaders.length; i++) {
    var val = response.headers.get(cspHeaders[i]);
    if (val) return val;
  }
  return null;
}

// --- Init ---

function init() {
  console.log('[CSP DSB] init() called, g_initPromise=' + (g_initPromise ? 'pending' : 'null'));

  // Promise-based dedup: if init() is already in progress, return the existing promise.
  // This replaces the old boolean g_initialized which couldn't handle concurrent calls.
  if (g_initPromise) return g_initPromise;

  g_initPromise = loadSettings().then(function(result) {
    console.log('[CSP DSB] init: loadSettings resolved, result.changed=' + result.changed);
    if (result.changed) {
      console.log('[CSP DSB] init: saving rules (IDs were assigned)');
      return saveRules();
    }
  }).then(function() {
    console.log('[CSP DSB] init: loading enabled state from storage...');
    return chrome.storage.local.get(['enabled']);
  }).then(function(local) {
    enabled = local.enabled === true;
    console.log('[CSP DSB] init: enabled=' + enabled + ', calling registerRules...');
    updateIcon();
    return registerRules(true);
  }).then(function() {
    console.log('[CSP DSB] init: COMPLETE. Global:', enabled,
      '| Rules:', rules.length,
      '| Active rules:', rules.filter(function(r) { return r.enabled; }).length);
    // Keep g_initPromise resolved so future callers chain instantly (no re-init needed)
    return { rules: rules, enabled: enabled };
  }).catch(function(err) {
    console.error('[CSP DSB] init: FAILED:', err);
    g_initPromise = null; // Allow retry on next call — only clear on failure
    throw err;
  });

  return g_initPromise;
}

// --- Messaging ---

chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {

  // Get full status
  if (message.type === 'getStatus') {
    sendResponse({
      enabled: enabled,
      debug: debug,
      rules: rules,
      activeRuleCount: rules.filter(function(r) { return r.enabled; }).length
    });
    return;
  }

  // Get settings (preferences only)
  if (message.type === 'getSettings') {
    chrome.storage.sync.get(DEFAULT_SETTINGS).then(function(pref) {
      sendResponse({
        enableAtStartup: pref.enableAtStartup || false,
        printDebugInfo: debug,
        rules: rules
      });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  // Save preferences (not rules)
  if (message.type === 'savePreferences') {
    chrome.storage.sync.set(message.pref).then(function() {
      debug = message.pref.printDebugInfo || false;
      return registerRules();
    }).then(function() {
      sendResponse({ success: true });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  // Global toggle
  if (message.type === 'toggle') {
    toggleGlobal().then(function() {
      sendResponse({ enabled: enabled });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  // Quick status for popup
  if (message.type === 'getEnabled') {
    sendResponse({
      enabled: enabled,
      ruleCount: rules.length,
      activeCount: rules.filter(function(r) { return r.enabled; }).length,
      canEnable: rules.length > 0 && rules.some(function(r) { return r.enabled; })
    });
    return;
  }

  // --- Rule CRUD ---

  if (message.type === 'addRule') {
    addRule(message.rule).then(function(rule) {
      sendResponse({ success: true, rule: rule });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (message.type === 'updateRule') {
    updateRule(message.ruleId, message.rule).then(function(rule) {
      sendResponse({ success: true, rule: rule });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (message.type === 'deleteRule') {
    deleteRule(message.ruleId).then(function() {
      sendResponse({ success: true });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (message.type === 'toggleRule') {
    toggleRule(message.ruleId).then(function(rule) {
      sendResponse({ success: true, rule: rule });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (message.type === 'moveRule') {
    moveRule(message.ruleId, message.direction).then(function(updatedRules) {
      sendResponse({ success: true, rules: updatedRules });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  // Auto-detect CSP header from a URL (used by popup when adding rule for current site)
  if (message.type === 'fetchCsp') {
    var targetUrl = message.url;
    if (!targetUrl) {
      sendResponse({ error: 'No URL provided' });
      return;
    }
    fetchCspFromUrl(targetUrl).then(function(cspValue) {
      sendResponse({ csp: cspValue });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  // Get all settings + rules + enabled state in one call (for popup)
  // Must wait for init() to complete so rules/enabled are loaded from storage
  if (message.type === 'getAllSettings') {
    init().then(function() {
      sendResponse({
        enableAtStartup: false,
        printDebugInfo: debug,
        rules: rules,
        enabled: enabled
      });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (message.type === 'replaceAllRules') {
    // Used by import/export
    rules = message.rules || [];
    // Ensure all have IDs
    rules.forEach(function(rule) {
      if (!rule.id) rule.id = generateRuleId();
    });
    saveRules().then(function() {
      return registerRules();
    }).then(function() {
      sendResponse({ success: true, rules: rules });
    }).catch(function(err) {
      sendResponse({ error: err.message });
    });
    return true;
  }
});

// --- Lifecycle ---

chrome.runtime.onInstalled.addListener(function(details) {
  console.log('[CSP DSB] onInstalled fired, reason=' + (details && details.reason));
  init();
});

chrome.runtime.onStartup.addListener(function() {
  console.log('[CSP DSB] onStartup fired — browser launched, initializing');
  init();
});

// Direct init call — catches all other cases:
// - Service worker wakeup (from terminated/idle state)
// - Chrome starts with extension already installed (onStartup may not always fire)
console.log('[CSP DSB] Service worker top-level execution, calling init()');
init();
