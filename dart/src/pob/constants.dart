/*
    Copyright (c) 2023 kaleidoscope-blockchain

    Unless specified otherwise, this work is licensed under the Creative Commons
    Attribution-NonCommercial 4.0 International License.

    To view a copy of this license, visit:
        http://creativecommons.org/licenses/by-nc/4.0/

    ----------------------------------------------------------------------------

    Licenses for the following files/packages may have different licenses: 

    1. `font.dart`
    
        Big by Glenn Chappell 4/93 -- based on Standard
        Includes ISO Latin-1
        Greek characters by Bruce Jakeway <pbjakeway@neumann.uwaterloo.ca>
        figlet release 2.2 -- November 1996
        Permission is hereby given to modify this font, as long as the
        modifier's name is placed on a comment line.

    2. Dart packages used in this software have the following licenses:
        BSD-3-Clause    (https://opensource.org/license/bsd-3-clause/)
        MIT             (https://opensource.org/license/mit/)
*/

import "dart:io";
import "dart:core";
import "dart:math";

import "dart:typed_data";
import 'package:system_info2/system_info2.dart';

import "release.dart"           as release;

final POB_RELEASE_VERSION       = release.version.trim();

final Map<String, String> ENV   = Platform.environment;

final RNG                       = Random.secure();

const UDP_CHUNK_SIZE            = 1448;
const UDP_HEADER_SIZE           = 40; // udp header size in bytes

const PROVER_PORT               = 11111;
const CHALLENGER_PORT           = 22222;
const HTTP_IPv4_PORT            = 33333;
const HTTP_IPv6_PORT            = 44444;

const HASH_SIZE_IN_BITS         = 32; // XXX 64 is better ?
const MAX_HASH                  = (1 << HASH_SIZE_IN_BITS) - 1;

const SERVER                    = "pob.witnesschain.com";
const SERVER_IPv4               = "IPv4." + SERVER;
const SERVER_IPv6               = "IPv6." + SERVER;

const SERVER_PORT               = ""; // :port

const API_VERSION               = "/api";
const BASE_URL                  = "https://" + SERVER      + SERVER_PORT + API_VERSION;
const BASE_URL_IPv4             = "https://" + SERVER_IPv4 + SERVER_PORT + API_VERSION;
const BASE_URL_IPv6             = "https://" + SERVER_IPv6 + SERVER_PORT + API_VERSION;

final LOGIN_URL                 = Uri.parse(BASE_URL + "/login"                 );
final LOGOUT_URL                = Uri.parse(BASE_URL + "/logout"                );
final PRE_LOGIN_URL             = Uri.parse(BASE_URL + "/pre-login"             );
final CHALLENGE_REQUEST_URL     = Uri.parse(BASE_URL + "/pob-challenge-request" );
final CHALLENGE_STATUS_URL      = Uri.parse(BASE_URL + "/pob-challenge-status"  );
final CHALLENGE_RESULT_URL      = Uri.parse(BASE_URL + "/pob-challenge-result"  );

final CLAIM_PUBLIC_IP_URL       = Uri.parse(BASE_URL + "/claim-public-ip"       );

final IP_INFO_URL               = Uri.parse(BASE_URL      + "/ip-info"          );
final IP_INFO_URL_IPv4          = Uri.parse(BASE_URL_IPv4 + "/ip-info"          );
final IP_INFO_URL_IPv6          = Uri.parse(BASE_URL_IPv6 + "/ip-info"          );

const WEBSOCKET_END_POINT       = SERVER      + SERVER_PORT + API_VERSION + "/ws";
const WEBSOCKET_END_POINT_IPv4  = SERVER_IPv4 + SERVER_PORT + API_VERSION + "/ws";
const WEBSOCKET_END_POINT_IPv6  = SERVER_IPv6 + SERVER_PORT + API_VERSION + "/ws";

final WEBSOCKET_GET_URL_IPv4    = Uri.parse("https://"  + WEBSOCKET_END_POINT_IPv4);
final WEBSOCKET_GET_URL_IPv6    = Uri.parse("https://"  + WEBSOCKET_END_POINT_IPv6);

const CONTENT_TYPE_JSON         = {
        "content-type" : "application/json"
};

const CHALLENGE_ID_LENGTH                   = 127;

const INDEX_START_CHALLENGE_ID              = 2;
const INDEX_END_CHALLENGE_ID                = INDEX_START_CHALLENGE_ID + CHALLENGE_ID_LENGTH - 1;

const INDEX_START_SEQUENCE_NUMBER           = INDEX_END_CHALLENGE_ID + 1;
const INDEX_START_RANDOM_NUMBER             = INDEX_START_SEQUENCE_NUMBER + 4;

const INDEX_START_PUBLIC_KEY_TYPE           = INDEX_START_RANDOM_NUMBER + 4;
const INDEX_START_PUBLIC_KEY_LENGTH         = INDEX_START_PUBLIC_KEY_TYPE + 1;

const INDEX_START_PUBLIC_KEY                = INDEX_START_PUBLIC_KEY_LENGTH + 1;

final FOR_2_SECONDS                         = Duration (seconds : 2);

final EMPTY_PACKET                          = Uint8List(0);

final ALL_VALID_CHALLENGE_STATES_FOR_CHALLENGER = {

    // PREVIOUS_STATE   : ALLOWED NEXT_STATE

    ""                  : "start_challenge",
    "start_challenge"   : "all_hashes",
    "all_hashes"        : "packet_bitmap",
    "packet_bitmap"     : "end_challenge",
};

const OS_TYPES = {
    "macos"     : "Darwin",
    "windows"   : "Windows_NT",
    "linux"     : "Linux",
    "unknown"   : "unknown"
};

final OS = OS_TYPES [Platform.operatingSystem] ?? "unknown";

final ARCHITECTURE_TYPES = {
    "arm64"     : "arm64",
    "amd64"     : "x64",
    "x86_64"    : "x64",
    "unknown"   : "unknown"
};

final arch = SysInfo.kernelArchitecture.toString() == "UNKNOWN" ? ENV["PROCESSOR_ARCHITECTURE"] : SysInfo.kernelArchitecture.toString();

final ARCHITECTURE = ARCHITECTURE_TYPES [arch?.toLowerCase()] ?? "unknown";

final LATEST_VERSION_URL            = Uri.parse("https://raw.githubusercontent.com/Proof-of-X/Proof-of-Backhaul/main/release/latest/version.txt");
final LATEST_VERSION_PROVER_URL     = Uri.parse("https://github.com/Proof-of-X/Proof-of-Backhaul/raw/main/release/latest/$ARCHITECTURE/$OS/run-pob-prover.exe");
final LATEST_VERSION_CHALLENGER_URL = Uri.parse("https://github.com/Proof-of-X/Proof-of-Backhaul/raw/main/release/latest/$ARCHITECTURE/$OS/run-pob-challenger.exe");
