/**
 * FIDO2/WebAuthn registration (profile page) and login-challenge
 * (wp-login.php?action=is_2fa) ceremonies. Uses the browser-native,
 * spec-standard PublicKeyCredential.parseCreationOptionsFromJSON() /
 * parseRequestOptionsFromJSON() / credential.toJSON() so no manual
 * base64url<->ArrayBuffer conversion is needed here -- the browser and
 * the server-side library (web-auth/webauthn-lib) both speak the same
 * standardized JSON shape directly.
 */
( function () {
	'use strict';

	function post( action, extra ) {
		var body = new URLSearchParams( Object.assign( { action: action }, extra || {} ) );
		return fetch( ISWebAuthn.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString(),
		} ).then( function ( r ) {
			return r.json();
		} );
	}

	function initRegister() {
		var button = document.getElementById( 'is-webauthn-register' );
		if ( ! button || ! window.PublicKeyCredential ) {
			return;
		}
		var status = document.getElementById( 'is-webauthn-register-status' );

		button.addEventListener( 'click', function () {
			status.textContent = '';
			button.disabled = true;

			post( 'is_webauthn_register_start', { nonce: button.dataset.nonce } )
				.then( function ( resp ) {
					if ( ! resp.success ) {
						throw new Error( resp.data && resp.data.message ? resp.data.message : 'Could not start registration.' );
					}
					var options = PublicKeyCredential.parseCreationOptionsFromJSON( resp.data.options );
					return navigator.credentials.create( { publicKey: options } );
				} )
				.then( function ( credential ) {
					var label = window.prompt( 'Name this security key (optional):', '' ) || '';
					return post( 'is_webauthn_register_finish', {
						nonce: button.dataset.nonce,
						label: label,
						credential: JSON.stringify( credential.toJSON() ),
					} );
				} )
				.then( function ( resp ) {
					if ( ! resp.success ) {
						throw new Error( resp.data && resp.data.message ? resp.data.message : 'Could not verify that security key.' );
					}
					window.location.reload();
				} )
				.catch( function ( err ) {
					status.textContent = err.message || 'Registration failed or was cancelled.';
					button.disabled = false;
				} );
		} );
	}

	function initLoginChallenge() {
		var button = document.getElementById( 'is-webauthn-login' );
		if ( ! button || ! window.PublicKeyCredential ) {
			return;
		}
		var status = document.getElementById( 'is-webauthn-login-status' );
		var token = button.dataset.token;
		var redirectTo = button.dataset.redirect;

		button.addEventListener( 'click', function () {
			status.textContent = '';
			button.disabled = true;

			post( 'is_webauthn_login_options', { token: token } )
				.then( function ( resp ) {
					if ( ! resp.success ) {
						throw new Error( resp.data && resp.data.message ? resp.data.message : 'Could not start verification.' );
					}
					var options = PublicKeyCredential.parseRequestOptionsFromJSON( resp.data.options );
					return navigator.credentials.get( { publicKey: options } );
				} )
				.then( function ( credential ) {
					return post( 'is_webauthn_login_verify', {
						token: token,
						redirect_to: redirectTo,
						credential: JSON.stringify( credential.toJSON() ),
					} );
				} )
				.then( function ( resp ) {
					if ( ! resp.success ) {
						throw new Error( resp.data && resp.data.message ? resp.data.message : 'Could not verify that security key.' );
					}
					window.location.href = resp.data.redirect_to;
				} )
				.catch( function ( err ) {
					status.textContent = err.message || 'Verification failed or was cancelled.';
					button.disabled = false;
				} );
		} );
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		initRegister();
		initLoginChallenge();
	} );
} )();
