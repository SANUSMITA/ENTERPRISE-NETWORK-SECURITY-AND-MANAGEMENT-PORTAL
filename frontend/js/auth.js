// ── Check login ───────────────────────────────────────
function checkLogin() {
  if (!localStorage.getItem('token')) {
    window.location.href = 'index.html';
    return false;
  }
  return true;
}

// ── Get current user info ─────────────────────────────
function getCurrentUser() {
  return {
    username:  localStorage.getItem('user')      || 'Unknown',
    full_name: localStorage.getItem('full_name') || 'Unknown',
    role:      localStorage.getItem('role')      || 'Viewer'
  };
}

// ── Check if user has permission ──────────────────────
function hasPermission(allowedRoles) {
  const role = localStorage.getItem('role');
  return allowedRoles.includes(role);
}

// ── Logout ────────────────────────────────────────────
function logout() {
  const username = localStorage.getItem('user');

  // Backend ko logout batao
  fetch('http://localhost:5000/api/logout', {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({ username })
  }).then(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('full_name');
    localStorage.removeItem('role');
    window.location.href = 'index.html';
  }).catch(() => {
    localStorage.clear();
    window.location.href = 'index.html';
  });
}

// ── Build sidebar based on role ───────────────────────
function buildSidebar(activePage) {
  const user = getCurrentUser();
  const role = user.role;

  // Pages each role can see
  
const permissions = {
  'Super Admin': ['threat-intel','ad-users','ad-groups','ad-audit','systems','system-logs','portal-users','login-history'],
  'IT Admin':    ['threat-intel','systems','system-logs'],
  'HR Admin':    ['ad-users','ad-groups','ad-audit'],
  'Viewer':      ['threat-intel']
};

  const allowed = permissions[role] || ['dashboard'];

  // All sidebar links
const allLinks = [
  { section: '🛡 Threat Intel' },
  { id:'threat-intel', label:'🛡 Threat Intelligence', href:'threat-intel.html' },
  { section: '👥 Active Directory' },
  { id:'ad-users',     label:'👤 Users',               href:'ad-users.html'     },
  { id:'ad-groups',    label:'🗂 Groups & OUs',        href:'ad-groups.html'    },
  { id:'ad-audit',     label:'📝 Audit Log',           href:'ad-audit.html'     },
  { section: '🖥 Systems' },
  { id:'systems',      label:'🖥 All Systems',         href:'systems.html'      },
  { id:'system-logs',  label:'📋 Login History',       href:'system-logs.html'  },
  { section: '⚙ Settings' },
  { id:'portal-users', label:'👥 Portal Users',        href:'portal-users.html' },
  { id:'login-history',label:'🕐 Login History',       href:'login-history.html'},
];
  // Build sidebar HTML
  let html = `<h2>⚡ NetAdmin Pro</h2>`;

  allLinks.forEach(link => {
    if (link.section) {
      // Check if any link in this section is allowed
      html += `<div class="sidebar-section">${link.section}</div>`;
    } else {
      if (allowed.includes(link.id)) {
        const isActive = activePage === link.id ? 'active' : '';
        html += `<a href="${link.href}" class="${isActive}">${link.label}</a>`;
      }
    }
  });

  // User info + logout at bottom
  html += `
    <div style="margin-top:auto;padding:8px 12px;border-top:1px solid #334155;">
      <p style="color:#94a3b8;font-size:0.75rem;">Logged in as</p>
      <p style="color:white;font-size:0.9rem;font-weight:bold;">${user.username}</p>
      <p style="color:#3b82f6;font-size:0.75rem;">${role}</p>
    </div>
    <a href="#" onclick="logout()" style="color:#ef4444;">🚪 Logout</a>
  `;

  document.querySelector('.sidebar').innerHTML = html;
}