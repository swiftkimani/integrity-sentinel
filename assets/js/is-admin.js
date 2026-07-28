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

	function initScanButton() {
		var btn = document.getElementById('is-scan-now-btn');
		if (!btn) {
			return;
		}
		var wrap = document.getElementById('is-scan-progress');
		var fill = document.getElementById('is-progress-fill');
		var text = document.getElementById('is-progress-text');

		function runBatch(runId) {
			post('is_scan_batch', { run_id: runId }).then(function (res) {
				if (!res.success) {
					text.textContent = window.ISAdmin.i18n.scanError + ' ' + (res.data && res.data.message ? res.data.message : '');
					return;
				}
				var data = res.data;
				var pct = data.files_total > 0 ? Math.round((data.files_scanned / data.files_total) * 100) : 0;
				fill.style.width = pct + '%';
				text.textContent = data.files_scanned + ' / ' + data.files_total + ' (' + pct + '%)';

				if (data.done) {
					text.textContent = window.ISAdmin.i18n.scanComplete + ' ' + text.textContent;
					btn.disabled = false;
					setTimeout(function () { window.location.reload(); }, 1200);
				} else {
					runBatch(runId);
				}
			}).catch(function () {
				text.textContent = window.ISAdmin.i18n.scanError;
			});
		}

		btn.addEventListener('click', function () {
			btn.disabled = true;
			wrap.style.display = '';
			text.textContent = window.ISAdmin.i18n.scanning;
			fill.style.width = '0%';

			post('is_start_scan').then(function (res) {
				if (!res.success) {
					text.textContent = window.ISAdmin.i18n.scanError;
					btn.disabled = false;
					return;
				}
				runBatch(res.data.run_id);
			});
		});
	}

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
					if (d.line) {
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
