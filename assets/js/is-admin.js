/**
 * Admin-side interactivity: the live scan progress bar and the findings
 * table's row actions / detail modal. Plain JS (fetch + FormData), no
 * build step, no external dependencies.
 */
(function () {
	'use strict';

	function post(action, extra) {
		var body = new FormData();
		body.append('action', action);
		body.append('nonce', window.ISAdmin.nonce);
		if (extra) {
			Object.keys(extra).forEach(function (key) {
				body.append(key, extra[key]);
			});
		}
		return fetch(window.ISAdmin.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(function (r) { return r.json(); });
	}

	// ---------------------------------------------------------------
	// Scan progress (dashboard)
	// ---------------------------------------------------------------

	var scanUi = null;

	function initScanUi() {
		var btn = document.getElementById('is-scan-now-btn');
		if (!btn) {
			return null;
		}
		return {
			btn: btn,
			wrap: document.getElementById('is-scan-progress'),
			fill: document.getElementById('is-progress-fill'),
			text: document.getElementById('is-progress-text')
		};
	}

	function updateBar(scanned, total) {
		var pct = total > 0 ? Math.round((scanned / total) * 100) : 0;
		scanUi.fill.style.width = pct + '%';
		scanUi.text.textContent = scanned + ' / ' + total + ' (' + pct + '%)';
	}

	function finishScanUi(data) {
		var extras = [];
		if (data && data.core_check && data.core_check.error) {
			extras.push(window.ISAdmin.i18n.scanError + ' ' + data.core_check.error);
		}
		if (data && data.plugin_check) {
			if (data.plugin_check.error) {
				extras.push(window.ISAdmin.i18n.scanError + ' ' + data.plugin_check.error);
			} else if (data.plugin_check.skipped && data.plugin_check.skipped.length) {
				extras.push(window.ISAdmin.i18n.notCheckable.replace('%d', data.plugin_check.skipped.length));
			}
		}
		scanUi.text.textContent = window.ISAdmin.i18n.scanComplete + ' ' + scanUi.text.textContent +
			(extras.length ? ' — ' + extras.join(' ') : '');
		scanUi.btn.disabled = false;
		setTimeout(function () { window.location.reload(); }, 1500);
	}

	// Another process (cron/WP-CLI) is driving the run: watch progress
	// via the read-only status endpoint instead of competing for batches.
	function pollStatus() {
		post('is_scan_status').then(function (res) {
			if (!res.success) {
				scanUi.text.textContent = window.ISAdmin.i18n.scanError;
				return;
			}
			if (res.data.running) {
				updateBar(res.data.files_scanned, res.data.files_total);
				setTimeout(pollStatus, 3000);
			} else {
				finishScanUi(null);
			}
		}).catch(function () {
			scanUi.text.textContent = window.ISAdmin.i18n.scanError;
		});
	}

	function runBatch(runId) {
		post('is_scan_batch', { run_id: runId }).then(function (res) {
			if (!res.success) {
				scanUi.text.textContent = window.ISAdmin.i18n.scanError + ' ' + (res.data && res.data.message ? res.data.message : '');
				scanUi.btn.disabled = false;
				return;
			}
			var data = res.data;
			if (data.error) {
				scanUi.text.textContent = window.ISAdmin.i18n.scanError + ' ' + data.error;
				scanUi.btn.disabled = false;
				return;
			}
			if (data.locked) {
				pollStatus();
				return;
			}
			updateBar(data.files_scanned, data.files_total);

			if (data.done) {
				finishScanUi(data);
			} else {
				runBatch(runId);
			}
		}).catch(function () {
			scanUi.text.textContent = window.ISAdmin.i18n.scanError;
		});
	}

	function startScanFlow() {
		scanUi.btn.disabled = true;
		scanUi.wrap.style.display = '';
		scanUi.text.textContent = window.ISAdmin.i18n.scanning;
		scanUi.fill.style.width = '0%';

		post('is_start_scan').then(function (res) {
			if (!res.success) {
				scanUi.text.textContent = window.ISAdmin.i18n.scanError;
				scanUi.btn.disabled = false;
				return;
			}
			runBatch(res.data.run_id);
		});
	}

	// If the page loads while a scan is already running (tab was closed
	// and reopened, or a cron scan is underway), pick the run back up
	// instead of showing a dead progress bar: drive batches if the lock
	// is free, or watch via polling if something else is driving.
	function resumeIfRunning() {
		post('is_scan_status').then(function (res) {
			if (!res.success || !res.data.running) {
				scanUi.wrap.style.display = 'none';
				scanUi.btn.disabled = false;
				return;
			}
			scanUi.btn.disabled = true;
			scanUi.wrap.style.display = '';
			scanUi.text.textContent = window.ISAdmin.i18n.scanInProgress;
			updateBar(res.data.files_scanned, res.data.files_total);
			runBatch(res.data.run_id);
		});
	}

	function initScanButton() {
		scanUi = initScanUi();
		if (!scanUi) {
			return;
		}
		scanUi.btn.addEventListener('click', startScanFlow);

		if (scanUi.wrap && scanUi.wrap.style.display !== 'none') {
			resumeIfRunning();
		}
	}

	// ---------------------------------------------------------------
	// Findings table
	// ---------------------------------------------------------------

	function initFindingActions() {
		document.querySelectorAll('.is-finding-action').forEach(function (link) {
			link.addEventListener('click', function (e) {
				e.preventDefault();
				var id = link.getAttribute('data-id');
				var status = link.getAttribute('data-status');
				post('is_set_finding_status', { finding_id: id, status: status }).then(function (res) {
					if (res.success) {
						var row = link.closest('tr');
						if (row) {
							row.style.opacity = '0.5';
						}
					}
				});
			});
		});
	}

	function initFindingModal() {
		var modal = document.getElementById('is-finding-modal');
		if (!modal) {
			return;
		}
		var body = document.getElementById('is-finding-modal-body');
		var closeBtn = modal.querySelector('.is-modal-close');

		function escapeHtml(str) {
			var div = document.createElement('div');
			div.textContent = str == null ? '' : String(str);
			return div.innerHTML;
		}

		document.querySelectorAll('.is-view-finding').forEach(function (link) {
			link.addEventListener('click', function (e) {
				e.preventDefault();
				var id = link.getAttribute('data-id');
				post('is_view_finding', { finding_id: id }).then(function (res) {
					if (!res.success) {
						return;
					}
					var d = res.data;
					var html = '<h2>' + escapeHtml(d.file_path) + '</h2>';
					html += '<p><strong>' + escapeHtml(d.severity) + '</strong> — ' + escapeHtml(d.detail) + '</p>';
					if (d.matches && d.matches.length) {
						d.matches.forEach(function (m) {
							html += '<p>Line ' + escapeHtml(m.line) + ':</p><pre>' + escapeHtml(m.snippet) + '</pre>';
						});
					} else if (d.line) {
						html += '<p>Line ' + escapeHtml(d.line) + ':</p><pre>' + escapeHtml(d.snippet) + '</pre>';
					}
					if (d.expected_md5) {
						html += '<p>Expected checksum: <code>' + escapeHtml(d.expected_md5) + '</code><br>Actual checksum: <code>' + escapeHtml(d.file_hash) + '</code></p>';
					}
					body.innerHTML = html;
					modal.style.display = 'flex';
				});
			});
		});

		closeBtn.addEventListener('click', function () {
			modal.style.display = 'none';
		});
		modal.addEventListener('click', function (e) {
			if (e.target === modal) {
				modal.style.display = 'none';
			}
		});
	}

	document.addEventListener('DOMContentLoaded', function () {
		initScanButton();
		initFindingActions();
		initFindingModal();
	});
})();
