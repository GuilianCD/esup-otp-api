var properties = require(__dirname + '/../properties/properties');
var api_controller = require(__dirname + '/../controllers/api');
var qrcode = require('qrcode');
var restify = require('restify');
var utils = require(__dirname + '/../services/utils');
var logger = require(__dirname + '/../services/logger').getInstance();
const { authenticator } = require('otplib');

const SimpleWebAuthnServer = require('@simplewebauthn/server');

const dayjs = require('dayjs');
const {bufferToBase64URLString} = require('../services/utils');


exports.name = "webauthn";

exports.user_activate = function(user, req, res, next) {
	user.webauthn.active = true;

	user.save(() => {
		res.status(200);
		res.send({
			code: "Ok",
		});
	});

	
}

// @TODO(Guilian): take values from esup.json
const rpName = "Université Paris 1";
const rpID = 'localhost';
// The URL at which registrations and authentications should occur
const origin = `http://${rpID}`;

/**
	* This function creates a nonce and sends it to the user.
	* This nonce should be signed and then sent back for 
	* validation, in confirm_user_activate.
	*
	* It also automatically invalidates any previous nonce,
	* by just overriding it.
	*
	*/
exports.get_method_secret = async function(user, req, res, next) {
	if(user.webauthn.active === false) {
		res.status(403);
		res.send({
			message: "Please activate the method before accessing this endpoint."
		});
		return;
	}

	const nonce = utils.bufferToBase64URLString(utils.generate_u8array_code(128));

	user.webauthn.registration.nonce = nonce;
	user.webauthn.registration.nonce_date = (new Date()).toISOString();

	user.save(() => {
		res.status(200);
		res.send({
			nonce: nonce,
			auths: user.webauthn.authenticators,
			user_id: utils.get_hash(user.uid),
			rp: properties.getEsupProperty("webauthnRelyingParty"),
		});
	});
}

/**
	* This function validates the signed nonce.
	*/
exports.confirm_user_activate = async function (user, req, res, next) {
	if(user.webauthn.active === false) {
		res.status(403);
		res.send({
			message: "Please activate the method before accessing this endpoint."
		});
		return;
	}

	if(!user.webauthn.registration.nonce) {
		res.status(403);
		res.send({
			message: "Cannot confirm method without first generating a challenge."
		});
		return;
	}

	if(!req.body) {
		res.status(400); // bad request payload
		res.send({
			message: "You need to send a signed challenge from the server.",
		});
		return;
	}

	const nonceDate = dayjs(user.webauthn.registration.nonce_date);
	const nowDate = dayjs();
	// 60 seconds
	if(nowDate.diff(nonceDate) >= 1000 * 60) {
		// 422 Unprocessable content : payload is correct but cannot process (timed out here)
		res.status(422); 
		res.send({
			message: "Your nonce timed out. Try generating another."
		});
		return;
	}

	let verification;
	try {
		verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
			response: req.body.cred,
			expectedChallenge: user.webauthn.registration.nonce,
			expectedOrigin: origin,
			expectedRPID: rpID,
			requireUserVerification: false,
		});
	} 
	catch (error) {
		//console.error(error);
		res.status(400);
		res.send({ error: error.message, isVerifyResponseFail: true });
		return;
	}

	let status = 400;
	let registered = false;

	if(verification.verified) {
		// remove the nonce from memory
		user.webauthn.registration.nonce = null;
		user.webauthn.registration.nonce_date = null;

		const { registrationInfo } = verification;
		const { credentialPublicKey, credentialID, counter } = registrationInfo;

		const newAuthenticator = {
			credentialID: bufferToBase64URLString(credentialID),
			credentialPublicKey: bufferToBase64URLString(credentialPublicKey),
			counter,
			name: null
		};

		// PREPEND the new authenticator
		user.webauthn.authenticators = [ ...user.webauthn.authenticators, newAuthenticator ];

		status = 200;
		registered = true;
	}
	
	user.save(() => {
		res.status(status);
		res.send({registered});
	});
}

exports.delete_method_special = function(user, req, res, next) {
	const pre_filter_length = user.webauthn.authenticators.length;
	user.webauthn.authenticators = user.webauthn.authenticators.filter(auth => (auth.credentialID !== req.params.authenticator_id));
	
	// if no elements were removed
	if(pre_filter_length <= user.webauthn.authenticators.length) {
		// => we didn't find  any matching credential
		// => bad request, not found
		res.status(404);
		res.send({
			message: "Unknown credential id",
		});
		return;
	}

	/*if(user.webauthn.authenticators.length === 0) {
		user.webauthn.active = false;
	}*/

	user.save(() => {
		res.status(200);
		res.send({});
	});
}

/**
	* Updates the name of the given factor
	*/
exports.change_method_special = function(user, req, res, next) {
	let index;
	for(index = 0; index < user.webauthn.authenticators.length; index++) {
		if(user.webauthn.authenticators[index].credentialID === req.params.authenticator_id) {
			break;
		}
	}

	

	if(index === user.webauthn.authenticators.length) {
		res.status(404);
		res.send({
			message: "Unknown credential id",
		});
		return;
	}

	if(req.body === undefined) {
		res.status(400);
		res.send({
			message: "You need to set a body",
		});
		return;
	}

	if(req.body.name === undefined) {
		res.status(400);
		res.send({
			message: "You need to set a new name in the body",
		});
		return;
	}

	const cool_regex = /^[a-zA-Z0-9_éêèà ]{1,20}$/g;

	if(cool_regex.test(req.body.name) === false) {
		res.status(400);
		res.send({
			message: "Invalid format",
		});
		return;
	}

	// APPARENTLY mongoose (or maybe mongo) does some """optimisation"""
	// where it does NOT write your changes if it doesn't detect them.
	// I don't know why I would need to be """protected""" like that, I 
	// know what I'm doing, but idk
	// => clone the object, change the attribute, override original.
	const updFactor = user.webauthn.authenticators[index];
	user.webauthn.authenticators[index] = {
		...updFactor,
		name: req.body.name.trim(),
	};

	user.save(() => {
		res.status(200);
		res.send({
		});
	});
}



/**
	* This function verifies you passed the correct otp,
	* otherwise it calls the next callback in line 
	* for totp submission
	*/
exports.verify_code = function(user, req, res, callbacks) {
	if(user.webauthn.registration.logged_in_otp) {
		if(user.webauthn.registration.logged_in_otp === req.params.otp) {
			user.webauthn.registration.logged_in_otp = null;
			user.save(() => {
				res.status(200);
				res.send({});
			});
			return;
		}
	}
		
	const next = callbacks.pop();
	next(user, req, res, callbacks);
}


/**
 * Vérifie que le facteur utilisé est valide.
 *
 * @param req requete HTTP contenant le nom la personne recherchee
 * @param res response HTTP
 * @param next permet d'appeler le prochain gestionnaire (handler)
 */
exports.verify_webauthn_auth = async function(user, req, res, callbacks) {
	logger.debug(utils.getFileName(__filename)+' '+"verify_code: "+user.uid);

	const response = req.body.response;
	const credID = req.body.credID;

	// find the index of the credential being used
	let usedAuth;
	for(usedAuth = 0; usedAuth < user.webauthn.authenticators.length; usedAuth++) {
		if(user.webauthn.authenticators[usedAuth].credentialID === credID) {
			break;
		}
	}

	if(usedAuth === user.webauthn.authenticators.length) {
		logger.info(utils.getFileName(__filename)+" Invalid authenticator by "+user.uid);
		res.status(403);
		res.send({
			message: "Please use a valid, previously-registered authenticator.",
		});
		return;
	}

	const base_auth = user.webauthn.authenticators[usedAuth];
	
	const uint8a = (base64url_of_buffer) => new Uint8Array(utils.base64URLStringToBuffer(base64url_of_buffer));

	const authenticator = {
		...base_auth,
		credentialID: uint8a(base_auth.credentialID),
		credentialPublicKey: uint8a(base_auth.credentialPublicKey),
	}
	
	let verification;
	try {
		verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
			response,
			expectedChallenge: user.webauthn.registration.nonce,
			expectedOrigin: origin,
			expectedRPID: rpID,
			requireUserVerification: false, //?
			authenticator
		});
	} catch (error) {
		console.error(error);
		console.error(error.cause);
		console.error(error.message);

		let error_payload = {
			message: error.message
		};

		if(error.message.includes("Unexpected authentication response origin")) {
			// sample input :
			// Error: Unexpected authentication response origin "http://localhost:8080", expected "http://localhost"

			const split = error.message.split('"');
			// split = ['Error: Unexpected authentication response origin ', 'http://localhost:8080', ' expected ', 'http://localhost']
			const got_host			= split[1];
			const expected_host	= split[3];

			error_payload = {
				message: {
					title: "L'adresse de cette page est différente de celle attendue par le serveur",
          desc: `Vous vous trouvez actuellement sur le domaine <b>${got_host}</b>, alors que le serveur s'attendais à ce que vous soyez sur le domaine, <b>${expected_host}</b>.<br>Vous êtes peut-être en train de subir une tentative de <a href="https://fr.wikipedia.org/wiki/Hame%C3%A7onnage">phishing</a>. Pensez à changer votre mot de passe si vous avez un doute, et n'hésitez pas à contacter un administrateur réseau.`,
					// "unforgivable" means the UI should try to prevent the user from retrying
					unforgivable: true,
				}
			}
		}

		console.log(error.message.includes("Unexpected authentication response origin"));


		res.status(400);
		res.send(error_payload);
		return;
	}

	const { verified } = verification;

	if(!verified) {
		logger.info(utils.getFileName(__filename)+" Invalid credentials by "+user.uid);
		res.status(400);
		res.send({
			message: "Failed to authenticate."
		});
	}

	// update counter
	user.webauthn.authenticators[usedAuth].counter = verification.authenticationInfo.newCounter;

	// create a token for cas-server
	user.webauthn.registration.logged_in_otp = utils.generate_string_code(16);

	user.save(() => {
		logger.info(utils.getFileName(__filename)+" Valid credentials by "+user.uid);
		res.status(200);
		res.send({token: user.webauthn.registration.logged_in_otp});
	});
}





exports.user_deactivate = function(user, req, res, next) {
	user.webauthn.active = false;
	user.webauthn.registered = false;
	user.save( function() {
		res.send({
			code: "Ok",
			message: "Deactivated webauthn"
		});
	});
}


