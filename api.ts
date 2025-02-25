import {
	api,
	body,
	endpoint,
	pathParams,
	request,
	response,
	headers,
	String,
	Integer,
	Float,
	DateTime,
	securityHeader,
}
	from "@airtasker/spot";

import {oa3server} from "@airtasker/spot/build/lib/src/syntax/oa3server";
import {oa3serverVariables} from "@airtasker/spot/build/lib/src/syntax/oa3serverVariables";

import {SecurityDefinitionsObject} from "@airtasker/spot/build/lib/src/generators/openapi2/openapi2-specification";
import {CookieParameterObject} from "@airtasker/spot/build/lib/src/generators/openapi3/openapi3-specification";

@api({
	name	: "Proof of X",
	version	: "1.0",
})
class Api
{
	@oa3server ({
		url: "https://api.witnesschain.com/"
	})

	productionServer (
		@oa3serverVariables variables: {
		}
	) {};

	@securityHeader
		"Cookie" : String;

/*
	Not sure how to specify exact cookie name

	@securityHeader
		@CookieParameterObject (
		){
			in : "cookie"
		};

	@securityHeader
		ApiKeySecuritySchemeObject(
			"type" : "apiKey";
		){};

	@securityHeader // "Cookie" : String;
		SecurityDefinitionsObject (
		){
			"type"	: "apiKey",
			"name"	: "x",
			"in"	: "cookie",
		};
*/
}

////////////////////////////////////////////////////////////////////////////////

interface SuccessResponse {

	/** -----
	Successful response always has a valid 'result'.
	**/

	result : {
		 success : boolean;
	}
}

interface FailureResponse {

	/** -----
	The 'error.message' contains the reason for the failure.
	**/

	error : {
		 message : String;
	}
}

interface StakingResponse {

	/** -----
	The failure due to requirement of 'payment' or 'staking'.

	The 'error.message' contains the reason for the failure.
	**/

	error : {
		 message : String;
	}
}

interface PreLoginCookieHeader {

	/** -----
	The cookies that were received after calling '/pre-login' API.
	**/

	"Cookie" : String
}

interface LoginCookieHeader {

	/** -----
	The cookies that were received after calling '/login' API.
	**/

	"Cookie" : String
}

////////////////////////////////////////////////////////////////////////////////

/**
	-----

	This API is to be called before logging in.

	It will return a 'message' that has to be signed and sent to '/login' API.

	This will also create a cookie;

	hence the '/login' API must be called in a session.
**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/pre-login",
	tags	: ["Session"],
})
class pre_login
{
	@request
	request(
		@body body: PreloginRequest,

		@pathParams	pathParams : {
      				proof_type: String;
    		},

	) {}

	@response({ status: 200 })
	successfulResponse(

		@body body: PreloginResponse,
		@headers headers : {

		/**
		-----
		The cookies that are to be sent to '/login' API
		**/

			"Set-Cookie" : String
		}
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body : FailureResponse
	) {}
}

interface PreloginRequest {
	/**
	-----
	The key used for login
	NOTE: when using 'ethereum' the 'publicKey = Address'
	**/

	publicKey		: String;

	/**
	-----
	The wallet where all the rewards go.

	if 'walletPublicKey' is NOT provided, then:
		walletPublicKey = publicKey

	As of now these are supported wallets:
		1. solana
		2. ethereum
	**/

	walletPublicKey?	: WalletPublicKey;

	/**
	-----
	The key-type of publicKey.

	As of now these are supported keyTypes:
		1. solana
		2. ethereum
	**/
	keyType			: "ethereum" | "solana";

	/**
	-----
 	The role the user intends to play after login:

		1. prover
			User who wants to prove what it offers to the network.

			Example: 'bandwidth', 'latency', 'disk', 'cpu' etc.

		2. challenger
			User who wants to challenge a 'prover'
			and earn rewards.

		3. payer
			An abstract entity/user who pays
			and requests for a challenge.

			A payer could be:
			the 'prover' itself, other users, or the blockchain.
	**/

	role			: "prover" | "challenger" | "payer";

	/**
	-----
	If the user is also part of another blockchain project/app,

	then the project-name/app-name can be provided here.

		e.g. "filecoin", "filecoin-station", "oort", etc.
	**/

	projectName?		: String;

	/**
	-----
	publicKey of the user associated with the

	'projectName' blockchain project/app.
	**/

	projectPublicKey?	: String;

	/**
	-----
	All claims.
	claims is dependent on proof_type,

	Example:
		For pob it is:
		{
			uplink_bandwidth	: Float; // The upload bandwidth in Mbps
			downlink_bandwidth	: Float; // The downlink bandwidth in Mbps
		}

		for pol it is:
		{
			country		: String;	// The 2 letter country code : e.g. US
			city		: String;	// e.g. Austin 
			region		: String;	// e.g. Texas

			latitude	: Float,
			longitude	: Float,
			radius		: Float,	// in KMs - with latitude, longitude as the center
		}

	**/
	claims : {
		"{claim-parameter-1}" : String | Integer | Float,
		"{claim-parameter-2}" : String | Integer | Float,
		"{claim-parameter-3}" : String | Integer | Float,
		"{claim-parameter-N}" : String | Integer | Float,
	};
}

interface WalletPublicKey {

	/**
	-----
	The 'solana' wallet public key
	**/
	solana	: String;

	/**
	-----
	The 'ethereum' wallet public key
	**/
	ethereum : String;
}


interface PreloginResponse {
	result : {

	/**
	-----
	A string to be signed using user's 'privateKey' to create a 'signature'.

	This 'signature' should be later sent in the '/login' API to login.
	**/
		message : String;
	}
}

/**
	-----

	This API logs in the user.

	The user should send the 'message' that was received during the '/pre-login';

	and must sign the 'message' using privateKey.

	And send it in the 'signature' field.
**/


@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/login",
	tags	: ["Session"]
})
class login
{
	@request
	request(
		@body		body	: LoginRequest,
		@headers	headers	: PreLoginCookieHeader,
		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body
			body: SuccessResponse,
		@headers
			headers : {

	/** -----
	the cookie after successful login.
	it must be presented for next api calls.
	**/

			"Set-Cookie" : String
		}
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse,
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body: FailureResponse,
	) {}

	@response({ status: 402 })
	paymentRequiredResponse(

	/** -----
	The response when a payment OR 'staking' is
	required before making this call.
	**/

		@body body: StakingResponse,
	) {}
}

/**
	-----

	Get logged in user information.
**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/user-info",
	tags	: ["User Information"]
})
class user_info
{
	@request
	request(
		@headers headers : LoginCookieHeader,
		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: UserInfoResponse
	) {}
}

interface UserInfoResponse {
	result : {
	/**
	-----

	will return 'null' if the user has not logged in
	**/
		id		: String;
		publicKey	: String;
		keyType		: String;

		city		: String;
		region		: String;
		country		: String;
	}
}

	/**
	-----

	Logs out the user.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/logout",
	tags	: ["Session"]
})
class logout
{
	@request
	request(
		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: SuccessResponse
	) {}
}


interface LoginRequest {

	/**
	-----
	The signature afer signing the 'message' with the 'privateKey'.

	The signature can be created using MetaMask/Phantom wallet.

	These signatures are generated through certain wallets/APIs.
    	e.g.
        	1. Wallets in browser (Metamask / Phantom)

        	2. Dart
            		(https://pub.dev/packages/eth_sig_util)

        	3. Python
            		(https://pypi.org/project/eth-account/)

	in Python it can be created as:

		from eth_account.messages import encode_defunct
		from eth_account import Account

		msg="<Message received from the pre-login response>"
		signature = sign(msg)

		def sign(msg):
		#
			# Hexadecimal key (private key)
			key = "<Your-Private-Key>"

			# Create the message hash
			msghash = encode_defunct(text=msg)

			# Sign the message
			signature = Account.sign_message(msghash, key)
			return "0x" + signature.signature.hex()
		#
	**/

	signature	: String;
}

////////////////////////////////////////////////////////////////////////////////

	/**
	-----

	Get information about a prover.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/prover",
	tags	: ["Prover Information"]
})
class prover
{
	@request
	request(
		@body		body	: ProverRequest,
		@headers	headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body : ProverResponse,
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}

interface ProverDetails {
	/**
	-----
	The unique 'id' of the prover.
	**/
	id			: String;

	/**
	-----
	The nickname of this prover
	**/
	name			: String;

	/**
	-----
	The estimate of geographic information based on IP address, please refer:
		https://www.npmjs.com/package/fast-geoip
	**/
	geoip			: GeoIP;

	/**
	-----
	Map of current claims
	**/
	claims : {
		"{claim-parameter-1}" : String | Integer | Float
		"{claim-parameter-2}" : String | Integer | Float
		"{claim-parameter-3}" : String | Integer | Float
		"{claim-parameter-N}" : String | Integer | Float
	};

	/**
	-----
	The latest time when the API server received a handshake from the prover.
	**/
	last_alive		: DateTime;

	/**
	-----
	The last time when the prover changed its IP
	**/
	last_ip_changed		: DateTime;

	keyType			: "ethereum";
	publicKey		: String;

	projectName		: String;
	projectPublicKey	: String;

	/**
	-----
	The challenge results of the prover
	**/
	results			: ResponseChallengeResult[];
}

interface ResponseChallengeResult
{
	/**
	-----
	The challenge id
	**/
	id			: String;

	/**
	-----
	The parameters of this challenge

	The other-challenge_parameters depends on proof_type.

	For pob it is:

		rate_of_packets_mbps		: Integer, // rate at which packets will arrive from a challenger
		max_packets_per_challenger		: Integer, // max packets that a challenger can send
		total_num_packets_for_challenge	: Integer  // total packets that a prover should receive
	**/
	challenge_parameters	: {
		number_of_challengers		: Integer,
		"{other-challenge-parameter-1}" : String | Integer | Float | boolean
		"{other-challenge-parameter-2}" : String | Integer | Float | boolean
		"{other-challenge-parameter-3}" : String | Integer | Float | boolean
		"{other-challenge-parameter-N}" : String | Integer | Float | boolean
	},

	challenge_start_time	: String,
	challenge_end_time	: String,

	/**
	-----
	The result collected and consolidated from the challengers

	The consolidated-result-parameters depends on proof_type.

	For pol it is:

	 KnowLock	: boolean,	// (web3) if KnowLock was able to validate the location
		"ipapi.co"	: boolean,	// (web2) if ipapi.co api was able to validate the location
		ipregistry	: boolean,	// (web2) if ipregistry api was able to validate the location
		maxmind	: boolean 	// (web2) if maxmind api was able to validate the location
	**/
	consolidated_result	: {
		"{consolidated-result-parameter-1}" : String | Integer | Float | boolean
		"{consolidated-result-parameter-2}" : String | Integer | Float | boolean
		"{consolidated-result-parameter-3}" : String | Integer | Float | boolean
		"{consolidated-result-parameter-N}" : String | Integer | Float | boolean
	},

	/**
	-----
	Prover details
	**/
	prover			: {
		claims		: {
			"{claim-parameter-1}" : String | Integer | Float
			"{claim-parameter-2}" : String | Integer | Float
			"{claim-parameter-N}" : String | Integer | Float
		}
	},

	/**
	-----
	The current state of the challenge
	**/
	state : "SUBMITTED_TO_CHALLENGE_COORDINATOR"	|
		"ACCEPTED_BY_CHALLENGE_COORDINATOR"	|
		"ERROR_NOT_ENOUGH_CHALLENGERS"		|
		"ENDED_WITH_PARTIAL_SUCCESS"		|
		"ERROR_ENDED_WITH_FAILURE"		|
		"ENDED_SUCCESSFULLY";
}

interface ChallengerDetails {
	/**
	-----
	The unique 'id' of the challenger.
	**/
	id			: String;

	/**
	-----
	The estimate of geographic information based on IP address, please refer:
		https://www.npmjs.com/package/fast-geoip
	**/
	geoip			: GeoIP;

	/**
	-----
	Map of claims
	**/
	claims : {
		"{claim-parameter-1}" : String | Integer | Float
		"{claim-parameter-2}" : String | Integer | Float
		"{claim-parameter-N}" : String | Integer | Float
	};

	/**
	-----
	The latest time when the API server received a handshake from the prover.
	**/
	last_alive		: DateTime;
}

interface GeoIP {
	range	: Integer[];	// [ 3479298048, 3479300095 ],
	country	: String;	// 'US',
	region  : String;	// 'TX',
	eu	: "0" | "1";	//
	timezone: String;	// 'America/Chicago',
	city	: String;	// 'San Antonio',
	ll	: Float[];	// [ 29.4969, -98.4032 ],
	metro	: Integer;	// 641,
	area	: Integer;	// 1000
}


interface ProverRequest {
	/**
	-----
 	The 'id' of the prover.
	**/
	id : String;
}

interface ProverResponse {
	/**
	-----
 	The details of the prover.
	**/
	result : ProverDetails
}

interface ChallengerRequest {
	/**
	-----
 	The 'id' of the challenger.
	**/
	id : String;
}

interface ChallengerResponse {
	/**
	-----
 	The details of the prover.
	**/
	result : ChallengerDetails
}

interface ChallengeResult {
	result			: Result[],
	message			: String,
	signature		: String,
	challenger		: String,
	challenge_start_time	: DateTime,
}

interface Result {
}


interface ProversRequest {

	/**
	-----
	the number of provers you wish to skip (default 0)
	**/

	skip?		: Integer,

	/**
	-----
	the MAX number of provers you wish to get (default 50)
	**/

	limit?		: Integer,
}

interface ChallengersRequest {

	/**
	-----
	the number of challengers you wish to skip (default 0)
	**/

	skip?		: Integer,

	/**
	-----
	the MAX number of challengers you wish to get (default 50)
	**/

	limit?		: Integer,
}



	/**
	-----
	Get all provers info.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/provers",
	tags	: ["Prover Information"]
})
class provers
{
	@request
	request(
		@body		body	: ProversRequest,
		@headers	headers : LoginCookieHeader,
		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body : ProversResponse,
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}

interface ProversResponse {
	result : {
		provers : ProverDetails[];
	}
}

	/**
	-----

	Get information about a challenger.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenger",
	tags	: ["Challenger Information"]
})
class challenger
{
	@request
	request(
		@body		body	: ChallengerRequest,
		@headers	headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body : ChallengerResponse,
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}




	/**
	-----
	Get all challengers info.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challengers",
	tags	: ["Challenger Information"]
})
class challengers
{
	@request
	request(
		@body		body	: ChallengersRequest,
		@headers	headers : LoginCookieHeader,
		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body : ChallengersResponse,
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}

interface ChallengersResponse {
	result : {
		challengers : ChallengerDetails[];
	}
}

////////////////////////////////////////////////////////////////////////////////

	/**
	-----

	Request to create a new challenge using DCL contracts.

	Before calling this api 'submitRequest()' smart contract must be called.

	And the 'challenge_id' after calling the 'submitRequest' must be provided.
	**/


@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenge-request-dcl",
	tags	: ["DCL Challenge"]
})
class challenge_request_dcl
{
	@request
	request(
		@body		body	: DCLChallengeRequest,

		@headers 	headers : LoginCookieHeader,

		@pathParams	pathParams: {
      			proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: ChallengeStatusResponse
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}


	/**
	-----
	Get the status of a given DCL challenge; along with results if any.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenge-status-dcl",
	tags	: ["DCL Challenge"]
})
class challenge_status_dcl
{
	@request
	request(
		@body		body	: DCLChallengeRequest,

		@headers 	headers : LoginCookieHeader,

		@pathParams	pathParams: {
      			proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: ResponseChallengeResult 
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}





interface ChallengeRequest {

	/**
	-----
 	The 'id' of the prover.
	**/
	prover		: String;

	/**
	-----
 	The transaction that was generated after calling the
	'startChallenge' smart contract.
	**/

	transaction	: String;

	/**
	-----
	The challenge_type depends on proof_type
		For example:
			For PoB it could be:
				1. uplink
				2. downlink
	**/

	challenge_type	: String;
}

interface DCLChallengeRequest {

	/**
	-----
 	The challenge_id that was generated after calling the
	DCL 'submitRequest' smart contract.
	**/

	challenge_id	: String;

	/**
	-----
	The challenge_type depends on proof_type
		For example:
			For PoB it could be:
				1. uplink
				2. downlink
	**/

	challenge_type	: String;
}

interface DCLChallengeStatusRequest {

	/**
	-----
 	The challenge_id that was generated after calling the
	DCL 'submitRequest' smart contract.
	**/

	challenge_id	: String;
}




	/**
	-----

	Request to create a new challenge.

	Before calling this api 'startChallenge()' smart contract must be called.

	And the 'transaction' after calling the 'startChallenge' must be provided.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenge-request",
	tags	: ["Challenge"]
})
class challenge_request
{
	@request
	request(
		@body		body	: ChallengeRequest,

		@headers 	headers : LoginCookieHeader,

		@pathParams	pathParams: {
      			proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: ChallengeStatusResponse
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}

	/**
	-----
	Get the status of a given challenge; along with results if any.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenge-status",
	tags	: ["Challenge"]
})
class challenge_status
{
	@request
	request(
		@body		body	: ChallengeStatusRequest,
		@headers	headers : LoginCookieHeader,

		@pathParams
    			pathParams: {
      				proof_type: String;
    			},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: ResponseChallengeResult
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}


	/**
	-----
	Post the results of a challenge.
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenge-result",
	tags	: ["Challenge"]
})
class challenge_result
{
	@request
	request(
		@body body: ChallengeResultRequest,
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: SuccessResponse
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}

interface ChallengeResultRequest {  // XXX to be fixed
	message_type	: "challenge_result";

	/**
	-----
	The result of a challenge - a JSON converted to a string.

	e.g. in JavaScript:

		message = JSON.stringify ({
			challenge_id,
			result,
		});

	The result contains fields that have been measured

	by the challenger:

		like "bandwidth" and "latency".
	**/

	message		:  {
		"start_time"		: String;
		"end_time"		: String;
		"challenge_succeeded"	: boolean;

		"{result-parameter-1}"	: String;
		"{result-parameter-2}"	: String;
		"{result-parameter-3}"	: String;
		"{result-parameter-N}"	: String;
	};

	/**
	-----
	The 'message' string signed using privateKey.
	**/

	signature	: String;
}


interface ChallengeHistory {
	id     			: String;
	challenge_start_time	: String;
	challenge_timeout	: String;
}

interface ChallengesResponse {
	result : ChallengeHistory [];
}

	/**
	-----

	History of challenges of the logged in user
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenges",
	tags	: ["Challenge"]
})
class challenges
{
	@request
	request(
		@headers 	headers : LoginCookieHeader,

		@pathParams	pathParams: {
      			proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: ChallengesResponse
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body: FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
}

interface ChallengeStatusRequest {
	/**
	-----
 	The transaction that was generated after calling the
	'startChallenge' smart contract.
	**/

	transaction : String;
}

interface ChallengeStatusResponse {
	result : {
		 challenge_id			: String;
                 challenge_status		:
				"SUBMITTED_TO_CHALLENGE_COORDINATOR"	|
				"ACCEPTED_BY_CHALLENGE_COORDINATOR"	|
				"ERROR_NOT_ENOUGH_CHALLENGERS"		|
				"ENDED_WITH_PARTIAL_SUCCESS"		|
				"ERROR_ENDED_WITH_FAILURE"		|
				"ENDED_SUCCESSFULLY";
	}
}


interface Claims {
	/**
	-----
	Map of all things a 'user' wants to claim.
	**/


	claims : {

		"{claim-parameter-1}" : String | Integer | Float;
		"{claim-parameter-2}" : String | Integer | Float;
		"{claim-parameter-3}" : String | Integer | Float;
		"{claim-parameter-N}" : String | Integer | Float;
	}
}



interface ClaimPublicIP {
	/**
	-----
	Claim which one of the interfaces have public-IP
	**/


	IPv4? : boolean,
	IPv6? : boolean
}



////////////////////////////////////////////////////////////////////////////////

	/**
	-----
	Update a 'user's proof-specific claims
	**/


@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/claims",
	tags	: ["Claims"]
})
class claims
{
	@request
	request(
		@body		body	: Claims,
		@headers	headers : LoginCookieHeader,


		@pathParams
    			pathParams: {
      				proof_type: String;
    			},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body : SuccessResponse
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body : FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
};

	/**
	-----
	Claim that a prover/challenger has public-IP
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/claim-public-ip",
	tags	: ["Claims"]
})
class claim_public_ip
{
	@request
	request(
		@body		body	: ClaimPublicIP,
		@headers	headers : LoginCookieHeader,


		@pathParams
    			pathParams: {
      				proof_type: String;
    			},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body : SuccessResponse
	) {}

	@response({ status: 400 })
	badRequestResponse(
		@body body : FailureResponse
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}
};



////////////////////////////////////////////////////////////////////////////////

	/**
	-----
	A websocket connection for:

		1. Sending heartbeat (websocket ping).
		2. Receiving notification regarding challenges.
	**/

@endpoint({
	method	: "GET",
	path	: "/proof/v1/:proof_type/ws",
	tags	: ["Websocket for Heartbeat and Notifications"]
})
class heartbeat
{
	@request
	request(
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	/**
	-----

	This opens up a websocket connection.

	This response is the successful response.
	**/

	@response({ status: 101 })
	successfulResponse(
		@headers headers : {
			"Upgrade"	: "websocket",
			"Connection"	: "Upgrade"
		}
	) {}

	@response({ status: 401 })
	unauthorizedResponse(
		@body body : FailureResponse
	) {}

	/**
	-----

	This message is sent to a 'prover' through websocket when a challenge

	has been scheduled

	// ignore the status code '201' given here.
	**/

	@response({ status: 201 })
	wsResponseForProver(
		@body body : ChallengeInfoForProver
	) {}

	/**
	-----

	This message is sent to a 'challenger' through websocket when a challenge

	has been scheduled

	// ignore the status code '202' given here.
	**/

	@response({ status: 202 })
	wsResponseForChallenger(
		@body body : ChallengeInfoForChallenger
	) {}

}

interface ChallengeInfoForProver
{
	message_type	: "challenge_for_prover",
	message		: {
		challenge_id			: String,
		challenge_start_time		: DateTime,
		challenge_timeout		: DateTime,
		challengers			: Challenger [],
		max_packets_per_challenger	: Integer,
		total_num_packets_for_challenge : Integer
	},
	signature				: String
}

interface ChallengeInfoForChallenger
{
	message_type	: "challenge_for_challenger",
	message		: {
		challenge_id			: String,
		prover				: Prover,
		challenge_start_time		: DateTime,
		challenge_timeout		: DateTime,
		num_packets			: Integer,
		rate_of_packets_mbps		: Float,
		total_num_packets_for_challenge : Integer,
	},
	signature				: String
}

interface Prover {
	ip		: String,
	publicKey	: String
}

interface Challenger {
	ip		: String,
	publicKey	: String
}

/**
	-----

	Get user's IP addresses as seen by the challenge co-ordinator
**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/ip-info",
	tags	: ["User Information"]
})
class ip_info
{
	@request
	request(
		@headers headers : LoginCookieHeader,
		@pathParams	pathParams : {
      				proof_type: String;
    		}
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: IPInfoResponse
	) {}
}

interface IPInfoResponse {
	result : {
	/**
	-----

	will return 'null' if the specific IP version is not available
	**/
		IPv4 : String | null;
		IPv6 : String | null;
	}
}

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/statistics",
	tags	: ["Statistics"]
})
class statistics
{
	@request
	request(
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: StatisticsResponse
	) {}
}

interface StatisticsResponse {
	result : {

	/**
	-----
	'online_provers' are the number of provers currently online.
	'num_provers'    are the total number of provers registered.
	**/
		online_provers		: Integer;
		num_provers		: Integer;

	/**
	-----
	'online_challenges' are the number of challengers currently online.
	'num_challengers'   are the total number of challengers registered.
	**/
		online_challenges	: Integer;
		num_challengers		: Integer;
	}
}


interface MetricsRequest {
	id : String;
}

interface MetricsResponse {
	result : {

		number_of_pings : {
			"{date-1}"	: Integer;
			"{date-2}"	: Integer;
			"{date-3}"	: Integer;
			"{date-N}"	: Integer;
		};

		number_of_logins : {
			"{date-1}"	: Integer;
			"{date-2}"	: Integer;
			"{date-3}"	: Integer;
			"{date-N}"	: Integer;
		};

		number_of_times_ip_changed : {
			"{date-1}"	: Integer;
			"{date-2}"	: Integer;
			"{date-3}"	: Integer;
			"{date-N}"	: Integer;
		};
	}
}

	/**
	-----
	Login and Ping metrics of a prover
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/prover-metrics",
	tags	: ["Statistics"]
})
class prover_metrics
{
	@request
	request(
		@body body	 : MetricsRequest,
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: MetricsResponse
	) {}
}

	/**
	-----
	Login and Ping metrics of a challenger
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/challenger-metrics",
	tags	: ["Statistics"]
})
class challenger_metrics
{
	@request
	request(
		@body body	 : MetricsRequest,
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: MetricsResponse
	) {}
}


interface CreateCampaignRequest {

	/** -----
	Name of the campaign	
	**/
	campaign	: String, 

	description	: String,	

	/** -----
	Type of campaign

		individual	: a single user participates in a photo campaign 
		group		: a group of users participates in a photo campaign 
		task		: a list of tasks to be performed by a single user
	**/
	type		: "individual" | "group" | "task",

	/** -----
	Time in ISO format	
	**/
	starts_at	: String, 
	ends_at		: String, 

	/** -----
	The maximum submissions that this campaign can accept	
	**/
	max_submissions	: Integer,

	/** -----
	If set to true, this campaign will be available to users	
	**/
	is_active	: boolean,

	/** -----
	What kind of rewards will be given to users	
	**/
	currency	: "POINTS",

	/** -----
	Total rewards and rewards per task	
	**/
	total_rewards	: Float,
	reward_per_task	: Float,

	/** -----
	Banner and poster for this campaign	
	**/
	banner_url	: String, 
	poster_url	: String, 

	/** -----
	Location of this campaign if any	
	the radius is in kms of circle within which the campaign is valid
	**/
	latitude?	: Float,
	longitude?	: Float,
	radius?		: Float,

	/** -----
	For group campaigns, the max distance the group can be from each other
	**/
	location_limit_in_meters?	: Integer,

	/** -----
	For group campaigns, the max time in minutes within which the referal link should be clicked 
	**/
	time_limit_in_minutes?		: Integer,


	/** -----
	Whitelist of addresses which can participate in this campaign	
	**/
	whitelist?			: String[], 

	/** -----
	For task campaigns, a dictionary of tasks	
	**/
	tasks? : {
		task1 : {
			fuel_required	: Float,
			type		: String,
			reward		: Float,
		},
	},
}

interface CreateCampaignResponse {
	result : {
		success : true,
		action	: String, 
	}
}

	/**
	-----
	Create a campaign	
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/create-campaign",
	tags	: ["Campaign"]
})
class create_campaign 
{
	@request
	request(
		@body body	 : CreateCampaignRequest,
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: CreateCampaignResponse 
	) {}
}

	/**
	-----
	Create a campaign	
	**/

@endpoint({
	method	: "POST",
	path	: "/proof/v1/:proof_type/create-campaign",
	tags	: ["Campaign"]
})
class edit_campaign 
{
	@request
	request(
		@body body	 : CreateCampaignRequest,
		@headers headers : LoginCookieHeader,

		@pathParams	pathParams : {
      				proof_type: String;
    		},
	) {}

	@response({ status: 200 })
	successfulResponse(
		@body body: CreateCampaignResponse 
	) {}
}
