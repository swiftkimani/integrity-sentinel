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

	// ---------------------------------------------------------------
	// Quarantine table
	// ---------------------------------------------------------------

	function initQuarantineDeleteToggles() {
		document.querySelectorAll('.is-quarantine-delete-toggle').forEach(function (btn) {
			btn.addEventListener('click', function () {
				var form = document.getElementById('is-quarantine-delete-form-' + btn.getAttribute('data-id'));
				if (form) {
					form.style.display = form.style.display === 'none' ? 'block' : 'none';
				}
			});
		});
	}

	// ---------------------------------------------------------------
	// Login Design: template grid + live preview + media picker
	// ---------------------------------------------------------------

	var SPLIT_TEMPLATES = ['sunrise', 'aurora-night', 'bubblegum', 'forest', 'monochrome', 'ocean', 'carousel', 'terminal', 'polaroid'];

	/** Wires an image URL field + Media Library picker + preview <img> + clear button, reused for the logo and the hero image. */
	function initImagePicker(opts) {
		var urlInput = document.getElementById(opts.urlId);
		var previewImg = document.getElementById(opts.previewId);
		var pickBtn = document.getElementById(opts.pickId);
		var clearBtn = document.getElementById(opts.clearId);
		if (!urlInput) {
			return;
		}

		urlInput.addEventListener('input', function () {
			var url = urlInput.value.trim();
			if (previewImg) {
				previewImg.src = url;
				previewImg.style.display = url ? '' : 'none';
			}
			if (clearBtn) {
				clearBtn.style.display = url ? '' : 'none';
			}
			if (opts.onChange) {
				opts.onChange(url);
			}
		});

		if (pickBtn) {
			// window.wp.media is checked here, at click time, not when this
			// listener is attached (page load) -- wp-media's own script can
			// still be loading at that point since there's no explicit
			// script dependency wiring it before is-admin.js, and checking
			// only once up front would permanently skip attaching the
			// listener if that race was lost.
			pickBtn.addEventListener('click', function (e) {
				e.preventDefault();
				if (!window.wp || !window.wp.media) {
					window.alert('The media library is still loading -- please wait a moment and try again.');
					return;
				}
				var frame = window.wp.media({ title: opts.mediaTitle || 'Select an image', multiple: false, library: { type: 'image' } });
				frame.on('select', function () {
					var attachment = frame.state().get('selection').first().toJSON();
					urlInput.value = attachment.url;
					urlInput.dispatchEvent(new Event('input'));
				});
				frame.open();
			});
		}

		if (clearBtn) {
			clearBtn.addEventListener('click', function () {
				urlInput.value = '';
				urlInput.dispatchEvent(new Event('input'));
			});
		}
	}

	function initLoginDesignPreview() {
		var preview = document.getElementById('is-login-preview');
		if (!preview) {
			return;
		}

		var colorInput = document.getElementById('is-login-color');
		var radiusInput = document.getElementById('is-login-radius');
		var radiusOutput = document.getElementById('is-login-radius-value');
		var previewLogo = document.getElementById('is-login-preview-logo');
		var previewHeading = document.getElementById('is-login-preview-heading');
		var previewSubheading = document.getElementById('is-login-preview-subheading');
		var previewHero = document.getElementById('is-login-preview-hero');
		var heroFields = document.getElementById('is-hero-fields');
		var headingInput = document.getElementById('is-hero-heading');
		var subheadingInput = document.getElementById('is-hero-subheading');
		var templateRadios = document.querySelectorAll('#is-template-grid input[type="radio"]');
		var positionRadios = document.querySelectorAll('input[name="is_login_design_settings[hero_position]"]');

		function applyTemplate(template) {
			preview.setAttribute('data-template', template);
			var isSplit = SPLIT_TEMPLATES.indexOf(template) !== -1;
			if (previewHero) {
				previewHero.style.display = isSplit ? '' : 'none';
			}
			if (heroFields) {
				heroFields.style.opacity = isSplit ? '' : '.4';
			}
			var galleryRow = document.getElementById('is-carousel-gallery-row');
			if (galleryRow) {
				galleryRow.style.display = 'carousel' === template ? '' : 'none';
			}
		}

		function applyPosition(position) {
			preview.setAttribute('data-position', position === 'right' ? 'right' : 'left');
		}

		templateRadios.forEach(function (radio) {
			radio.addEventListener('change', function () {
				applyTemplate(radio.value);
				templateRadios.forEach(function (r) {
					r.closest('.is-template-card').classList.toggle('is-selected', r.checked);
				});
			});
			if (radio.checked) {
				applyTemplate(radio.value);
			}
		});

		positionRadios.forEach(function (radio) {
			radio.addEventListener('change', function () {
				if (radio.checked) {
					applyPosition(radio.value);
				}
			});
			if (radio.checked) {
				applyPosition(radio.value);
			}
		});

		if (colorInput) {
			colorInput.addEventListener('input', function () {
				preview.style.setProperty('--is-login-color', colorInput.value);
			});
		}

		if (radiusInput) {
			radiusInput.addEventListener('input', function () {
				preview.style.setProperty('--is-login-radius', radiusInput.value + 'px');
				if (radiusOutput) {
					radiusOutput.textContent = radiusInput.value + 'px';
				}
			});
		}

		if (headingInput && previewHeading) {
			headingInput.addEventListener('input', function () {
				previewHeading.textContent = headingInput.value;
			});
		}

		if (subheadingInput && previewSubheading) {
			subheadingInput.addEventListener('input', function () {
				previewSubheading.textContent = subheadingInput.value;
			});
		}

		initImagePicker({
			urlId: 'is-login-logo-url',
			previewId: 'is-login-logo-preview',
			pickId: 'is-login-logo-pick',
			clearId: 'is-login-logo-clear',
			mediaTitle: 'Select a logo',
			onChange: function (url) {
				if (!previewLogo) {
					return;
				}
				previewLogo.innerHTML = url ? '<img src="' + url.replace(/"/g, '&quot;') + '" alt="">' : previewLogo.textContent;
			}
		});

		initImagePicker({
			urlId: 'is-hero-image-url',
			previewId: 'is-hero-image-preview',
			pickId: 'is-hero-image-pick',
			clearId: 'is-hero-image-clear',
			mediaTitle: 'Select a hero image'
		});

		// "Open real preview": save an unsaved draft server-side and open
		// the actual wp-login.php rendering it, instead of the stand-in
		// mockup above. window.open() is called synchronously (before the
		// fetch resolves) so browsers don't treat it as a blocked popup.
		var previewBtn = document.getElementById('is-login-preview-btn');
		var designForm = document.getElementById('is-login-design-form');
		if (previewBtn && designForm) {
			previewBtn.addEventListener('click', function () {
				var status = document.getElementById('is-login-preview-status');
				var win = window.open('', '_blank');
				var body = new FormData(designForm);
				body.append('action', 'is_preview_login_design');
				body.append('nonce', window.ISAdmin.nonce);
				if (status) {
					status.textContent = 'Preparing preview…';
				}
				// Read as text first, not r.json() directly: a PHP notice/
				// warning ahead of the real JSON output (or a nonce
				// failure, which wp_die()s a bare "-1") would otherwise
				// fail silently inside r.json() with no way to tell why.
				fetch(window.ISAdmin.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
					.then(function (r) { return r.text(); })
					.then(function (text) {
						var res;
						try {
							res = JSON.parse(text);
						} catch (parseErr) {
							console.error('[Integrity Sentinel] preview request returned a non-JSON response:', text);
							throw parseErr;
						}
						if (res && res.success && res.data && res.data.preview_url && win) {
							win.location.href = res.data.preview_url;
							if (status) {
								status.textContent = '';
							}
						} else {
							if (win) {
								win.close();
							}
							var message = res && res.data && res.data.message ? res.data.message : 'Could not open preview.';
							if (status) {
								status.textContent = message;
							}
							console.error('[Integrity Sentinel] preview request failed:', res);
						}
					})
					.catch(function (err) {
						if (win) {
							win.close();
						}
						if (status) {
							status.textContent = 'Could not open preview.';
						}
						console.error('[Integrity Sentinel] preview request error:', err);
					});
			});
		}
	}

	document.addEventListener('DOMContentLoaded', function () {
		initScanButton();
		initFindingActions();
		initFindingModal();
		initQuarantineDeleteToggles();
		initLoginDesignPreview();
	});
})();
