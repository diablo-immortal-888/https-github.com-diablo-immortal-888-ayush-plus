window.renderDashboard = function () {
  const host = document.getElementById('personalDashboard');
  if (!host) return;
  const docs = read(STORAGE.docs, []);
  host.hidden = false;
  document.querySelectorAll('#page-dashboard>.stats,#page-dashboard>.layout').forEach(node => node.hidden = true);
  if (!docs.length) {
    host.innerHTML = `<section class="card empty-state"><div class="stat-ico">✦</div><h2 data-ui-static>Your workspace is ready</h2><p class="sub" data-ui-static>Upload a health record to start a private, organized history.</p><button class="btn btn-primary" type="button" onclick="go('upload')">＋ Upload your first record</button></section>`;
    return;
  }
  const recent = docs.slice(0, 4);
  host.innerHTML = `<section class="card"><div class="section-head"><div><h2>Your health records</h2><p class="sub">${docs.length} record${docs.length === 1 ? '' : 's'} for ${escapeHtml(person)}</p></div><button class="btn btn-primary" type="button" onclick="go('upload')">＋ Upload</button></div>${recent.map(doc => `<div class="report"><div class="doc-icon">▤</div><div class="report-info"><b>${escapeHtml(doc.name)}</b><small>${escapeHtml(doc.date || 'Date not detected')}</small></div><span class="tag">${escapeHtml(doc.category || 'Record')}</span></div>`).join('')}<button class="text-btn" type="button" onclick="go('timeline')">Open health timeline →</button></section>`;
};
