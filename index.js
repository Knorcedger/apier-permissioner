var authenticator = require('apier-authenticator');
var responseBuilder = require('apier-responsebuilder');
var reqlog = require('reqlog');

module.exports = function(access) {
	return function(req, res, next) {
		reqlog.info('permissioner', access);

		// check which case is, array or string
		if (Array.isArray(access)) {
			// load the user to validate him against the permissions
			authenticator.authenticate(req)
			.then(function() {
				// access null means the service is public
				// we do the check here so that the authenticator will find the user that makes the request
				// even if the permission is null, not all users can see and schema attributes
				if (access[0] === 'null') {
					next();
				} else {
					var user = req.activeUser;
					if (user === 'null') {
						responseBuilder.error(req, res, 'INVALID_SESSION');
					} else {
						if (user.type === 'admin' ||
						access.indexOf(user.type) !== -1) {
							next();
						} else {
							responseBuilder.error(req, res, 'NO_PERMISSION');
						}
					}
				}
			});
		} else {
			authenticator.authenticate(req)
			.then(function() {
				var user = req.activeUser;

				// if the expression is true or user is admin
				if (user === 'null') {
					responseBuilder.error(req, res, 'INVALID_SESSION');
				} else {
					if (user.type === 'admin' || eval(access)) {
						next();
					} else {
						responseBuilder.error(req, res, 'NO_PERMISSION');
					}
				}
			});
		}
	};
};
