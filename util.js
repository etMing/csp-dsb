// --- CSP Parser & Utilities -------------------------------------------------

var CSP_DIRECTIVE_REX = /^\s*(([a-zA-Z\d\-]+)(\s.*)?)?$/;

// Normalize a CSP source value for comparison.
function csp_normalize_source(src, directive) {
  var r;
  if (directive === 'plugin-types') {
    return src.toLowerCase();
  }
  if (/^'(none|self|unsafe-inline|unsafe-eval|strict-dynamic|unsafe-hashes|unsafe-allow-redirects)'$/i.test(src)) {
    return src.toLowerCase();
  }
  r = src.match(/^'(nonce|sha256|sha384|sha512)-([a-z\d+/]+={0,2})'$/i);
  if (r) {
    return "'" + r[1].toLowerCase() + "-" + r[2] + "'";
  }
  r = src.match(/^([a-zA-Z][a-zA-Z\d+\-.]*:)$/);
  if (r) {
    return src.toLowerCase();
  }
  r = src.match(/^([a-zA-Z][a-zA-Z\d+\-.]*:\/\/)?((\*\.)?[a-zA-Z\d][a-zA-Z\d\-]*(\.[a-zA-Z\d\-]+)*|\*)(:(\d+|\*))?(\/.*)?/);
  if (r) {
    return (r[1] ? r[1].toLowerCase() : '') + r[2].toLowerCase() + (r[5] ? r[5] : '') + (r[7] ? r[7] : '');
  }
  return src.toLowerCase();
}

// Parse user CSP policy text into structured directives.
function cspParse(csp_str) {
  var ro = { error: 'n/a', policy: [] };
  var dir_names = {};
  var a = csp_str.split(';');

  for (var i = 0; i < a.length; i++) {
    var r = a[i].match(CSP_DIRECTIVE_REX);
    if (!r) {
      ro.error = 'wrong CSP directive: ' + a[i].substring(0, 40);
      return ro;
    }
    if (!r[2]) continue;

    var name = r[2].toLowerCase();
    var value = r[3] ? r[3] : '';

    if (dir_names[name] == null) {
      dir_names[name] = i;
      var add = [];
      var remove = [];
      var removeDirective = false;

      value.split(' ').forEach(function(src) {
        if (!src) return;
        var rm = src.match(/^'remove':(.*)/i);
        if (rm) {
          if (!rm[1]) {
            ro.error = "wrong 'remove': in " + name;
            return;
          }
          var ss = rm[1].split(',');
          for (var j = 0; j < ss.length; j++) {
            var s = ss[j];
            if (s.toLowerCase() === "'directive'") {
              removeDirective = true;
            } else if (/^\/.*\/$/.test(s)) {
              try {
                remove.push(new RegExp(s.substring(1, s.length - 1)));
              } catch (e) {
                ro.error = e + ' ' + src + ' in ' + name;
              }
            } else if (s.length > 0) {
              remove.push(csp_normalize_source(s));
            }
          }
        } else {
          add.push(csp_normalize_source(src));
        }
      });

      ro.policy.push({
        name: name,
        add: add,
        remove: remove,
        removeDirective: removeDirective
      });
    }
  }

  ro.error = null;
  return ro;
}

// Convert parsed CSP policy back to a header value string.
// Returns null if the policy is "no-csp" (remove CSP entirely).
function cspPolicyToHeaderValue(policy) {
  if (policy.some(function(d) { return d.name === 'no-csp'; })) {
    return null;
  }

  var parts = [];
  for (var i = 0; i < policy.length; i++) {
    var directive = policy[i];
    if (directive.removeDirective) continue;
    var sources = directive.add.slice();
    if (sources.length > 0) {
      parts.push(directive.name + ' ' + sources.join(' '));
    } else {
      parts.push(directive.name);
    }
  }
  return parts.length > 0 ? parts.join('; ') : '';
}

// Parse comma-separated URL patterns.
function parseUrls(strUrls) {
  var urls = [];
  if (typeof strUrls === 'string' && strUrls) {
    var ar = strUrls.split(',');
    for (var i = 0; i < ar.length; i++) {
      var url = ar[i].trim();
      if (url) urls.push(url);
    }
  }
  return urls;
}

// Convert a match-pattern URL to a declarativeNetRequest urlFilter.
function urlToFilter(urlPattern) {
  var p = urlPattern.trim();

  if (p === '<all_urls>' || p === '*://*/*' || p === '*' || p === '*://*') {
    return '*';
  }

  p = p.replace(/\/\*$/, '');

  if (p.indexOf('*://') === 0) {
    return '||' + p.substring(4) + '^';
  }

  if (p.indexOf('https://') === 0 || p.indexOf('http://') === 0) {
    return '|' + p + '^';
  }

  return p + '^';
}

// --- Color Scheme Helpers ----------------------------------------------------

function setupColorScheme(colorScheme) {
  if (colorScheme === 'auto') {
    document.body.style.colorScheme = 'light dark';
    var isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.body.classList[isDark ? 'add' : 'remove']('dark-mode');
  } else {
    document.body.style.colorScheme = colorScheme;
    document.body.classList[colorScheme === 'dark' ? 'add' : 'remove']('dark-mode');
  }
}

function onPrefersColorSchemeDarkChange(ev) {
  if (document.documentElement.dataset.colorScheme === 'auto') {
    document.body.classList[ev.matches ? 'add' : 'remove']('dark-mode');
  }
}

// --- Declarative Net Request Rule Builder ------------------------------------

var CSP_HEADER_NAMES = [
  'content-security-policy',
  'content-security-policy-report-only',
  'x-content-security-policy',
  'x-content-security-policy-report-only',
  'x-webkit-csp'
];

var CACHE_HEADER_NAMES = ['cache-control', 'expires', 'pragma'];

// Generate a unique ID for new rules.
function generateRuleId() {
  return 'r' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
}

// Validate a single rule object. Returns null if valid, error string if not.
function validateRule(rule) {
  if (!rule || typeof rule !== 'object') return 'Invalid rule';
  if (!rule.url || typeof rule.url !== 'string' || !rule.url.trim()) {
    return 'URL is required';
  }
  if (!rule.policy || typeof rule.policy !== 'string' || !rule.policy.trim()) {
    return 'CSP policy is required';
  }
  var ro = cspParse(rule.policy.trim());
  if (ro.error) return ro.error;
  if (ro.policy.length === 0) return 'No valid directive in policy';
  return null;
}

// Generate all DNR rules from the rule list.
// Each user-rule may generate multiple DNR rules (one per CSP header + optional cache rules).
// Returns: { dnrRules: Array, ruleIndex: Array } where ruleIndex[i] = userRuleId
function generateAllDnrRules(userRules, noCache) {
  var dnrRules = [];
  var ruleIndex = [];  // maps DNR rule id -> user rule id
  var nextId = 1;

  var resourceTypes = ['main_frame', 'sub_frame'];

  for (var i = 0; i < userRules.length; i++) {
    var rule = userRules[i];
    if (!rule.enabled) continue;

    var policy = cspParse(rule.policy);
    if (policy.error || policy.policy.length === 0) continue;

    var isNoCsp = policy.policy.some(function(d) { return d.name === 'no-csp'; });
    var headerValue = isNoCsp ? null : cspPolicyToHeaderValue(policy.policy);
    var urlFilter = urlToFilter(rule.url);

    if (isNoCsp) {
      // Remove ALL CSP headers for this URL
      dnrRules.push({
        id: nextId,
        priority: 2,
        action: {
          type: 'modifyHeaders',
          responseHeaders: CSP_HEADER_NAMES.map(function(h) {
            return { header: h, operation: 'remove' };
          })
        },
        condition: { urlFilter: urlFilter, resourceTypes: resourceTypes }
      });
      ruleIndex[nextId] = rule.id;
      nextId++;
    } else if (headerValue) {
      // Set CSP header for this URL
      dnrRules.push({
        id: nextId,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          responseHeaders: CSP_HEADER_NAMES.map(function(h) {
            return { header: h, operation: 'set', value: headerValue };
          })
        },
        condition: { urlFilter: urlFilter, resourceTypes: resourceTypes }
      });
      ruleIndex[nextId] = rule.id;
      nextId++;
    }

    // No-cache: add cache header removal rules
    if (noCache && (isNoCsp || headerValue)) {
      dnrRules.push({
        id: nextId,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          responseHeaders: CACHE_HEADER_NAMES.map(function(h) {
            return { header: h, operation: 'remove' };
          })
        },
        condition: { urlFilter: urlFilter, resourceTypes: resourceTypes }
      });
      ruleIndex[nextId] = rule.id;
      nextId++;
    }
  }

  return { dnrRules: dnrRules, ruleIndex: ruleIndex, nextId: nextId };
}

// --- Logging -----------------------------------------------------------------

function log_message(msg) {
  try {
    chrome.runtime.sendMessage({ type: 'log', str: msg }).catch(function() {});
  } catch (e) {
    // popup/options might not be open
  }
}
