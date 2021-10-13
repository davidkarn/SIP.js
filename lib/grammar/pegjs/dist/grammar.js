import { NameAddrHeader } from "../../name-addr-header";
import { URI } from "../../uri";
export class SyntaxError extends Error {
    constructor(message, expected, found, location) {
        super();
        this.message = message;
        this.expected = expected;
        this.found = found;
        this.location = location;
        this.name = "SyntaxError";
        if (typeof Error.captureStackTrace === "function") {
            Error.captureStackTrace(this, SyntaxError);
        }
    }
    static buildMessage(expected, found) {
        function hex(ch) {
            return ch.charCodeAt(0).toString(16).toUpperCase();
        }
        function literalEscape(s) {
            return s
                .replace(/\\/g, "\\\\")
                .replace(/"/g, "\\\"")
                .replace(/\0/g, "\\0")
                .replace(/\t/g, "\\t")
                .replace(/\n/g, "\\n")
                .replace(/\r/g, "\\r")
                .replace(/[\x00-\x0F]/g, (ch) => "\\x0" + hex(ch))
                .replace(/[\x10-\x1F\x7F-\x9F]/g, (ch) => "\\x" + hex(ch));
        }
        function classEscape(s) {
            return s
                .replace(/\\/g, "\\\\")
                .replace(/\]/g, "\\]")
                .replace(/\^/g, "\\^")
                .replace(/-/g, "\\-")
                .replace(/\0/g, "\\0")
                .replace(/\t/g, "\\t")
                .replace(/\n/g, "\\n")
                .replace(/\r/g, "\\r")
                .replace(/[\x00-\x0F]/g, (ch) => "\\x0" + hex(ch))
                .replace(/[\x10-\x1F\x7F-\x9F]/g, (ch) => "\\x" + hex(ch));
        }
        function describeExpectation(expectation) {
            switch (expectation.type) {
                case "literal":
                    return "\"" + literalEscape(expectation.text) + "\"";
                case "class":
                    const escapedParts = expectation.parts.map((part) => {
                        return Array.isArray(part)
                            ? classEscape(part[0]) + "-" + classEscape(part[1])
                            : classEscape(part);
                    });
                    return "[" + (expectation.inverted ? "^" : "") + escapedParts + "]";
                case "any":
                    return "any character";
                case "end":
                    return "end of input";
                case "other":
                    return expectation.description;
            }
        }
        function describeExpected(expected1) {
            const descriptions = expected1.map(describeExpectation);
            let i;
            let j;
            descriptions.sort();
            if (descriptions.length > 0) {
                for (i = 1, j = 1; i < descriptions.length; i++) {
                    if (descriptions[i - 1] !== descriptions[i]) {
                        descriptions[j] = descriptions[i];
                        j++;
                    }
                }
                descriptions.length = j;
            }
            switch (descriptions.length) {
                case 1:
                    return descriptions[0];
                case 2:
                    return descriptions[0] + " or " + descriptions[1];
                default:
                    return descriptions.slice(0, -1).join(", ")
                        + ", or "
                        + descriptions[descriptions.length - 1];
            }
        }
        function describeFound(found1) {
            return found1 ? "\"" + literalEscape(found1) + "\"" : "end of input";
        }
        return "Expected " + describeExpected(expected) + " but " + describeFound(found) + " found.";
    }
}
function peg$parse(input, options) {
    options = options !== undefined ? options : {};
    const peg$FAILED = {};
    const peg$startRuleIndices = { Contact: 118, Name_Addr_Header: 155, Record_Route: 175, Request_Response: 80, SIP_URI: 45, Subscription_State: 185, Supported: 190, Require: 181, Via: 193, absoluteURI: 83, Call_ID: 117, Content_Disposition: 129, Content_Length: 134, Content_Type: 135, CSeq: 145, displayName: 121, Event: 148, From: 150, host: 52, Max_Forwards: 153, Min_SE: 212, Proxy_Authenticate: 156, quoted_string: 40, Refer_To: 177, Replaces: 178, Session_Expires: 209, stun_URI: 216, To: 191, turn_URI: 222, uuid: 225, WWW_Authenticate: 208, challenge: 157, sipfrag: 229, Referred_By: 230 };
    let peg$startRuleIndex = 118;
    const peg$consts = [
        "\r\n",
        peg$literalExpectation("\r\n", false),
        /^[0-9]/,
        peg$classExpectation([["0", "9"]], false, false),
        /^[a-zA-Z]/,
        peg$classExpectation([["a", "z"], ["A", "Z"]], false, false),
        /^[0-9a-fA-F]/,
        peg$classExpectation([["0", "9"], ["a", "f"], ["A", "F"]], false, false),
        /^[\0-\xFF]/,
        peg$classExpectation([["\0", "\xFF"]], false, false),
        /^["]/,
        peg$classExpectation(["\""], false, false),
        " ",
        peg$literalExpectation(" ", false),
        "\t",
        peg$literalExpectation("\t", false),
        /^[a-zA-Z0-9]/,
        peg$classExpectation([["a", "z"], ["A", "Z"], ["0", "9"]], false, false),
        ";",
        peg$literalExpectation(";", false),
        "/",
        peg$literalExpectation("/", false),
        "?",
        peg$literalExpectation("?", false),
        ":",
        peg$literalExpectation(":", false),
        "@",
        peg$literalExpectation("@", false),
        "&",
        peg$literalExpectation("&", false),
        "=",
        peg$literalExpectation("=", false),
        "+",
        peg$literalExpectation("+", false),
        "$",
        peg$literalExpectation("$", false),
        ",",
        peg$literalExpectation(",", false),
        "-",
        peg$literalExpectation("-", false),
        "_",
        peg$literalExpectation("_", false),
        ".",
        peg$literalExpectation(".", false),
        "!",
        peg$literalExpectation("!", false),
        "~",
        peg$literalExpectation("~", false),
        "*",
        peg$literalExpectation("*", false),
        "'",
        peg$literalExpectation("'", false),
        "(",
        peg$literalExpectation("(", false),
        ")",
        peg$literalExpectation(")", false),
        "%",
        peg$literalExpectation("%", false),
        function () { return " "; },
        function () { return ':'; },
        /^[!-~]/,
        peg$classExpectation([["!", "~"]], false, false),
        /^[\x80-\uFFFF]/,
        peg$classExpectation([["\x80", "\uFFFF"]], false, false),
        /^[\x80-\xBF]/,
        peg$classExpectation([["\x80", "\xBF"]], false, false),
        /^[a-f]/,
        peg$classExpectation([["a", "f"]], false, false),
        "`",
        peg$literalExpectation("`", false),
        "<",
        peg$literalExpectation("<", false),
        ">",
        peg$literalExpectation(">", false),
        "\\",
        peg$literalExpectation("\\", false),
        "[",
        peg$literalExpectation("[", false),
        "]",
        peg$literalExpectation("]", false),
        "{",
        peg$literalExpectation("{", false),
        "}",
        peg$literalExpectation("}", false),
        function () { return "*"; },
        function () { return "/"; },
        function () { return "="; },
        function () { return "("; },
        function () { return ")"; },
        function () { return ">"; },
        function () { return "<"; },
        function () { return ","; },
        function () { return ";"; },
        function () { return ":"; },
        function () { return "\""; },
        /^[!-']/,
        peg$classExpectation([["!", "'"]], false, false),
        /^[*-[]/,
        peg$classExpectation([["*", "["]], false, false),
        /^[\]-~]/,
        peg$classExpectation([["]", "~"]], false, false),
        function (contents) {
            return contents;
        },
        /^[#-[]/,
        peg$classExpectation([["#", "["]], false, false),
        /^[\0-\t]/,
        peg$classExpectation([["\0", "\t"]], false, false),
        /^[\x0B-\f]/,
        peg$classExpectation([["\x0B", "\f"]], false, false),
        /^[\x0E-\x7F]/,
        peg$classExpectation([["\x0E", "\x7F"]], false, false),
        function () {
            options = options || { data: {} };
            options.data.uri = new URI(options.data.scheme, options.data.user, options.data.host, options.data.port);
            delete options.data.scheme;
            delete options.data.user;
            delete options.data.host;
            delete options.data.host_type;
            delete options.data.port;
        },
        function () {
            options = options || { data: {} };
            options.data.uri = new URI(options.data.scheme, options.data.user, options.data.host, options.data.port, options.data.uri_params, options.data.uri_headers);
            delete options.data.scheme;
            delete options.data.user;
            delete options.data.host;
            delete options.data.host_type;
            delete options.data.port;
            delete options.data.uri_params;
            if (options.startRule === 'SIP_URI') {
                options.data = options.data.uri;
            }
        },
        "sips",
        peg$literalExpectation("sips", true),
        "sip",
        peg$literalExpectation("sip", true),
        function (uri_scheme) {
            options = options || { data: {} };
            options.data.scheme = uri_scheme;
        },
        function () {
            options = options || { data: {} };
            options.data.user = decodeURIComponent(text().slice(0, -1));
        },
        function () {
            options = options || { data: {} };
            options.data.password = text();
        },
        function () {
            options = options || { data: {} };
            options.data.host = text();
            return options.data.host;
        },
        function () {
            options = options || { data: {} };
            options.data.host_type = 'domain';
            return text();
        },
        /^[a-zA-Z0-9_\-]/,
        peg$classExpectation([["a", "z"], ["A", "Z"], ["0", "9"], "_", "-"], false, false),
        function () {
            options = options || { data: {} };
            options.data.host_type = 'IPv6';
            return text();
        },
        "::",
        peg$literalExpectation("::", false),
        function () {
            options = options || { data: {} };
            options.data.host_type = 'IPv6';
            return text();
        },
        function () {
            options = options || { data: {} };
            options.data.host_type = 'IPv4';
            return text();
        },
        "25",
        peg$literalExpectation("25", false),
        /^[0-5]/,
        peg$classExpectation([["0", "5"]], false, false),
        "2",
        peg$literalExpectation("2", false),
        /^[0-4]/,
        peg$classExpectation([["0", "4"]], false, false),
        "1",
        peg$literalExpectation("1", false),
        /^[1-9]/,
        peg$classExpectation([["1", "9"]], false, false),
        function (port) {
            options = options || { data: {} };
            port = parseInt(port.join(''));
            options.data.port = port;
            return port;
        },
        "transport=",
        peg$literalExpectation("transport=", true),
        "udp",
        peg$literalExpectation("udp", true),
        "tcp",
        peg$literalExpectation("tcp", true),
        "sctp",
        peg$literalExpectation("sctp", true),
        "tls",
        peg$literalExpectation("tls", true),
        function (transport) {
            options = options || { data: {} };
            if (!options.data.uri_params)
                options.data.uri_params = {};
            options.data.uri_params['transport'] = transport.toLowerCase();
        },
        "user=",
        peg$literalExpectation("user=", true),
        "phone",
        peg$literalExpectation("phone", true),
        "ip",
        peg$literalExpectation("ip", true),
        function (user) {
            options = options || { data: {} };
            if (!options.data.uri_params)
                options.data.uri_params = {};
            options.data.uri_params['user'] = user.toLowerCase();
        },
        "method=",
        peg$literalExpectation("method=", true),
        function (method) {
            options = options || { data: {} };
            if (!options.data.uri_params)
                options.data.uri_params = {};
            options.data.uri_params['method'] = method;
        },
        "ttl=",
        peg$literalExpectation("ttl=", true),
        function (ttl) {
            options = options || { data: {} };
            if (!options.data.params)
                options.data.params = {};
            options.data.params['ttl'] = ttl;
        },
        "maddr=",
        peg$literalExpectation("maddr=", true),
        function (maddr) {
            options = options || { data: {} };
            if (!options.data.uri_params)
                options.data.uri_params = {};
            options.data.uri_params['maddr'] = maddr;
        },
        "lr",
        peg$literalExpectation("lr", true),
        function () {
            options = options || { data: {} };
            if (!options.data.uri_params)
                options.data.uri_params = {};
            options.data.uri_params['lr'] = undefined;
        },
        function (param, value) {
            options = options || { data: {} };
            if (!options.data.uri_params)
                options.data.uri_params = {};
            if (value === null) {
                value = undefined;
            }
            else {
                value = value[1];
            }
            options.data.uri_params[param.toLowerCase()] = value;
        },
        function (hname, hvalue) {
            hname = hname.join('').toLowerCase();
            hvalue = hvalue.join('');
            options = options || { data: {} };
            if (!options.data.uri_headers)
                options.data.uri_headers = {};
            if (!options.data.uri_headers[hname]) {
                options.data.uri_headers[hname] = [hvalue];
            }
            else {
                options.data.uri_headers[hname].push(hvalue);
            }
        },
        function () {
            options = options || { data: {} };
            // lots of tests fail if this isn't guarded...
            if (options.startRule === 'Refer_To') {
                options.data.uri = new URI(options.data.scheme, options.data.user, options.data.host, options.data.port, options.data.uri_params, options.data.uri_headers);
                delete options.data.scheme;
                delete options.data.user;
                delete options.data.host;
                delete options.data.host_type;
                delete options.data.port;
                delete options.data.uri_params;
            }
        },
        "//",
        peg$literalExpectation("//", false),
        function () {
            options = options || { data: {} };
            options.data.scheme = text();
        },
        peg$literalExpectation("SIP", true),
        function () {
            options = options || { data: {} };
            options.data.sip_version = text();
        },
        "INVITE",
        peg$literalExpectation("INVITE", false),
        "ACK",
        peg$literalExpectation("ACK", false),
        "VXACH",
        peg$literalExpectation("VXACH", false),
        "OPTIONS",
        peg$literalExpectation("OPTIONS", false),
        "BYE",
        peg$literalExpectation("BYE", false),
        "CANCEL",
        peg$literalExpectation("CANCEL", false),
        "REGISTER",
        peg$literalExpectation("REGISTER", false),
        "SUBSCRIBE",
        peg$literalExpectation("SUBSCRIBE", false),
        "NOTIFY",
        peg$literalExpectation("NOTIFY", false),
        "REFER",
        peg$literalExpectation("REFER", false),
        "PUBLISH",
        peg$literalExpectation("PUBLISH", false),
        function () {
            options = options || { data: {} };
            options.data.method = text();
            return options.data.method;
        },
        function (status_code) {
            options = options || { data: {} };
            options.data.status_code = parseInt(status_code.join(''));
        },
        function () {
            options = options || { data: {} };
            options.data.reason_phrase = text();
        },
        function () {
            options = options || { data: {} };
            options.data = text();
        },
        function () {
            var idx, length;
            options = options || { data: {} };
            length = options.data.multi_header.length;
            for (idx = 0; idx < length; idx++) {
                if (options.data.multi_header[idx].parsed === null) {
                    options.data = null;
                    break;
                }
            }
            if (options.data !== null) {
                options.data = options.data.multi_header;
            }
            else {
                options.data = -1;
            }
        },
        function () {
            var header;
            options = options || { data: {} };
            if (!options.data.multi_header)
                options.data.multi_header = [];
            try {
                header = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                delete options.data.uri;
                delete options.data.displayName;
                delete options.data.params;
            }
            catch (e) {
                header = null;
            }
            options.data.multi_header.push({ 'position': peg$currPos,
                'offset': location().start.offset,
                'parsed': header
            });
        },
        function (displayName) {
            displayName = text().trim();
            if (displayName[0] === '\"') {
                displayName = displayName.substring(1, displayName.length - 1);
            }
            options = options || { data: {} };
            options.data.displayName = displayName;
        },
        "q",
        peg$literalExpectation("q", true),
        function (q) {
            options = options || { data: {} };
            if (!options.data.params)
                options.data.params = {};
            options.data.params['q'] = q;
        },
        "expires",
        peg$literalExpectation("expires", true),
        function (expires) {
            options = options || { data: {} };
            if (!options.data.params)
                options.data.params = {};
            options.data.params['expires'] = expires;
        },
        function (delta_seconds) {
            return parseInt(delta_seconds.join(''));
        },
        "0",
        peg$literalExpectation("0", false),
        function () {
            return parseFloat(text());
        },
        function (param, value) {
            options = options || { data: {} };
            if (!options.data.params)
                options.data.params = {};
            if (value === null) {
                value = undefined;
            }
            else {
                value = value[1];
            }
            options.data.params[param.toLowerCase()] = value;
        },
        "render",
        peg$literalExpectation("render", true),
        "session",
        peg$literalExpectation("session", true),
        "icon",
        peg$literalExpectation("icon", true),
        "alert",
        peg$literalExpectation("alert", true),
        function () {
            options = options || { data: {} };
            if (options.startRule === 'Content_Disposition') {
                options.data.type = text().toLowerCase();
            }
        },
        "handling",
        peg$literalExpectation("handling", true),
        "optional",
        peg$literalExpectation("optional", true),
        "required",
        peg$literalExpectation("required", true),
        function (length) {
            options = options || { data: {} };
            options.data = parseInt(length.join(''));
        },
        function () {
            options = options || { data: {} };
            options.data = text();
        },
        "text",
        peg$literalExpectation("text", true),
        "image",
        peg$literalExpectation("image", true),
        "audio",
        peg$literalExpectation("audio", true),
        "video",
        peg$literalExpectation("video", true),
        "application",
        peg$literalExpectation("application", true),
        "message",
        peg$literalExpectation("message", true),
        "multipart",
        peg$literalExpectation("multipart", true),
        "x-",
        peg$literalExpectation("x-", true),
        function (cseq_value) {
            options = options || { data: {} };
            options.data.value = parseInt(cseq_value.join(''));
        },
        function (expires) { options = options || { data: {} }; options.data = expires; },
        function (event_type) {
            options = options || { data: {} };
            options.data.event = event_type.toLowerCase();
        },
        function () {
            options = options || { data: {} };
            var tag = options.data.tag;
            options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
            if (tag) {
                options.data.setParam('tag', tag);
            }
        },
        "tag",
        peg$literalExpectation("tag", true),
        function (tag) { options = options || { data: {} }; options.data.tag = tag; },
        function (forwards) {
            options = options || { data: {} };
            options.data = parseInt(forwards.join(''));
        },
        function (min_expires) { options = options || { data: {} }; options.data = min_expires; },
        function () {
            options = options || { data: {} };
            options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
        },
        "digest",
        peg$literalExpectation("Digest", true),
        "realm",
        peg$literalExpectation("realm", true),
        function (realm) { options = options || { data: {} }; options.data.realm = realm; },
        "domain",
        peg$literalExpectation("domain", true),
        "nonce",
        peg$literalExpectation("nonce", true),
        function (nonce) { options = options || { data: {} }; options.data.nonce = nonce; },
        "opaque",
        peg$literalExpectation("opaque", true),
        function (opaque) { options = options || { data: {} }; options.data.opaque = opaque; },
        "stale",
        peg$literalExpectation("stale", true),
        "true",
        peg$literalExpectation("true", true),
        function () { options = options || { data: {} }; options.data.stale = true; },
        "false",
        peg$literalExpectation("false", true),
        function () { options = options || { data: {} }; options.data.stale = false; },
        "algorithm",
        peg$literalExpectation("algorithm", true),
        "md5",
        peg$literalExpectation("MD5", true),
        "md5-sess",
        peg$literalExpectation("MD5-sess", true),
        function (algorithm) {
            options = options || { data: {} };
            options.data.algorithm = algorithm.toUpperCase();
        },
        "qop",
        peg$literalExpectation("qop", true),
        "auth-int",
        peg$literalExpectation("auth-int", true),
        "auth",
        peg$literalExpectation("auth", true),
        function (qop_value) {
            options = options || { data: {} };
            options.data.qop || (options.data.qop = []);
            options.data.qop.push(qop_value.toLowerCase());
        },
        function (rack_value) {
            options = options || { data: {} };
            options.data.value = parseInt(rack_value.join(''));
        },
        function () {
            var idx, length;
            options = options || { data: {} };
            length = options.data.multi_header.length;
            for (idx = 0; idx < length; idx++) {
                if (options.data.multi_header[idx].parsed === null) {
                    options.data = null;
                    break;
                }
            }
            if (options.data !== null) {
                options.data = options.data.multi_header;
            }
            else {
                options.data = -1;
            }
        },
        function () {
            var header;
            options = options || { data: {} };
            if (!options.data.multi_header)
                options.data.multi_header = [];
            try {
                header = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
                delete options.data.uri;
                delete options.data.displayName;
                delete options.data.params;
            }
            catch (e) {
                header = null;
            }
            options.data.multi_header.push({ 'position': peg$currPos,
                'offset': location().start.offset,
                'parsed': header
            });
        },
        function () {
            options = options || { data: {} };
            options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
        },
        function () {
            options = options || { data: {} };
            if (!(options.data.replaces_from_tag && options.data.replaces_to_tag)) {
                options.data = -1;
            }
        },
        function () {
            options = options || { data: {} };
            options.data = {
                call_id: options.data
            };
        },
        "from-tag",
        peg$literalExpectation("from-tag", true),
        function (from_tag) {
            options = options || { data: {} };
            options.data.replaces_from_tag = from_tag;
        },
        "to-tag",
        peg$literalExpectation("to-tag", true),
        function (to_tag) {
            options = options || { data: {} };
            options.data.replaces_to_tag = to_tag;
        },
        "early-only",
        peg$literalExpectation("early-only", true),
        function () {
            options = options || { data: {} };
            options.data.early_only = true;
        },
        function (head, r) { return r; },
        function (head, tail) { return list(head, tail); },
        function (value) {
            options = options || { data: {} };
            if (options.startRule === 'Require') {
                options.data = value || [];
            }
        },
        function (rseq_value) {
            options = options || { data: {} };
            options.data.value = parseInt(rseq_value.join(''));
        },
        "active",
        peg$literalExpectation("active", true),
        "pending",
        peg$literalExpectation("pending", true),
        "terminated",
        peg$literalExpectation("terminated", true),
        function () {
            options = options || { data: {} };
            options.data.state = text();
        },
        "reason",
        peg$literalExpectation("reason", true),
        function (reason) {
            options = options || { data: {} };
            if (typeof reason !== 'undefined')
                options.data.reason = reason;
        },
        function (expires) {
            options = options || { data: {} };
            if (typeof expires !== 'undefined')
                options.data.expires = expires;
        },
        "retry_after",
        peg$literalExpectation("retry_after", true),
        function (retry_after) {
            options = options || { data: {} };
            if (typeof retry_after !== 'undefined')
                options.data.retry_after = retry_after;
        },
        "deactivated",
        peg$literalExpectation("deactivated", true),
        "probation",
        peg$literalExpectation("probation", true),
        "rejected",
        peg$literalExpectation("rejected", true),
        "timeout",
        peg$literalExpectation("timeout", true),
        "giveup",
        peg$literalExpectation("giveup", true),
        "noresource",
        peg$literalExpectation("noresource", true),
        "invariant",
        peg$literalExpectation("invariant", true),
        function (value) {
            options = options || { data: {} };
            if (options.startRule === 'Supported') {
                options.data = value || [];
            }
        },
        function () {
            options = options || { data: {} };
            var tag = options.data.tag;
            options.data = new NameAddrHeader(options.data.uri, options.data.displayName, options.data.params);
            if (tag) {
                options.data.setParam('tag', tag);
            }
        },
        "ttl",
        peg$literalExpectation("ttl", true),
        function (via_ttl_value) {
            options = options || { data: {} };
            options.data.ttl = via_ttl_value;
        },
        "maddr",
        peg$literalExpectation("maddr", true),
        function (via_maddr) {
            options = options || { data: {} };
            options.data.maddr = via_maddr;
        },
        "received",
        peg$literalExpectation("received", true),
        function (via_received) {
            options = options || { data: {} };
            options.data.received = via_received;
        },
        "branch",
        peg$literalExpectation("branch", true),
        function (via_branch) {
            options = options || { data: {} };
            options.data.branch = via_branch;
        },
        "rport",
        peg$literalExpectation("rport", true),
        function (response_port) {
            options = options || { data: {} };
            if (typeof response_port !== 'undefined')
                options.data.rport = response_port.join('');
        },
        function (via_protocol) {
            options = options || { data: {} };
            options.data.protocol = via_protocol;
        },
        peg$literalExpectation("UDP", true),
        peg$literalExpectation("TCP", true),
        peg$literalExpectation("TLS", true),
        peg$literalExpectation("SCTP", true),
        function (via_transport) {
            options = options || { data: {} };
            options.data.transport = via_transport;
        },
        function () {
            options = options || { data: {} };
            options.data.host = text();
        },
        function (via_sent_by_port) {
            options = options || { data: {} };
            options.data.port = parseInt(via_sent_by_port.join(''));
        },
        function (ttl) {
            return parseInt(ttl.join(''));
        },
        function (deltaSeconds) {
            options = options || { data: {} };
            if (options.startRule === 'Session_Expires') {
                options.data.deltaSeconds = deltaSeconds;
            }
        },
        "refresher",
        peg$literalExpectation("refresher", false),
        "uas",
        peg$literalExpectation("uas", false),
        "uac",
        peg$literalExpectation("uac", false),
        function (endpoint) {
            options = options || { data: {} };
            if (options.startRule === 'Session_Expires') {
                options.data.refresher = endpoint;
            }
        },
        function (deltaSeconds) {
            options = options || { data: {} };
            if (options.startRule === 'Min_SE') {
                options.data = deltaSeconds;
            }
        },
        "stuns",
        peg$literalExpectation("stuns", true),
        "stun",
        peg$literalExpectation("stun", true),
        function (scheme) {
            options = options || { data: {} };
            options.data.scheme = scheme;
        },
        function (host) {
            options = options || { data: {} };
            options.data.host = host;
        },
        "?transport=",
        peg$literalExpectation("?transport=", false),
        "turns",
        peg$literalExpectation("turns", true),
        "turn",
        peg$literalExpectation("turn", true),
        function (transport) {
            options = options || { data: {} };
            options.data.transport = transport;
        },
        function () {
            options = options || { data: {} };
            options.data = text();
        },
        "Referred-By",
        peg$literalExpectation("Referred-By", false),
        "b",
        peg$literalExpectation("b", false),
        "cid",
        peg$literalExpectation("cid", false)
    ];
    const peg$bytecode = [
        peg$decode("2 \"\"6 7!"),
        peg$decode("4\"\"\"5!7#"),
        peg$decode("4$\"\"5!7%"),
        peg$decode("4&\"\"5!7'"),
        peg$decode(";'.# &;("),
        peg$decode("4(\"\"5!7)"),
        peg$decode("4*\"\"5!7+"),
        peg$decode("2,\"\"6,7-"),
        peg$decode("2.\"\"6.7/"),
        peg$decode("40\"\"5!71"),
        peg$decode("22\"\"6273.\x89 &24\"\"6475.} &26\"\"6677.q &28\"\"6879.e &2:\"\"6:7;.Y &2<\"\"6<7=.M &2>\"\"6>7?.A &2@\"\"6@7A.5 &2B\"\"6B7C.) &2D\"\"6D7E"),
        peg$decode(";).# &;,"),
        peg$decode("2F\"\"6F7G.} &2H\"\"6H7I.q &2J\"\"6J7K.e &2L\"\"6L7M.Y &2N\"\"6N7O.M &2P\"\"6P7Q.A &2R\"\"6R7S.5 &2T\"\"6T7U.) &2V\"\"6V7W"),
        peg$decode("%%2X\"\"6X7Y/5#;#/,$;#/#$+#)(#'#(\"'#&'#/\"!&,)"),
        peg$decode("%%$;$0#*;$&/,#; /#$+\")(\"'#&'#.\" &\"/=#$;$/&#0#*;$&&&#/'$8\":Z\" )(\"'#&'#"),
        peg$decode(";..\" &\""),
        peg$decode("%$;'.# &;(0)*;'.# &;(&/?#28\"\"6879/0$;//'$8#:[# )(#'#(\"'#&'#"),
        peg$decode("%%$;2/&#0#*;2&&&#/g#$%$;.0#*;.&/,#;2/#$+\")(\"'#&'#0=*%$;.0#*;.&/,#;2/#$+\")(\"'#&'#&/#$+\")(\"'#&'#/\"!&,)"),
        peg$decode("4\\\"\"5!7].# &;3"),
        peg$decode("4^\"\"5!7_"),
        peg$decode("4`\"\"5!7a"),
        peg$decode(";!.) &4b\"\"5!7c"),
        peg$decode("%$;).\x95 &2F\"\"6F7G.\x89 &2J\"\"6J7K.} &2L\"\"6L7M.q &2X\"\"6X7Y.e &2P\"\"6P7Q.Y &2H\"\"6H7I.M &2@\"\"6@7A.A &2d\"\"6d7e.5 &2R\"\"6R7S.) &2N\"\"6N7O/\x9E#0\x9B*;).\x95 &2F\"\"6F7G.\x89 &2J\"\"6J7K.} &2L\"\"6L7M.q &2X\"\"6X7Y.e &2P\"\"6P7Q.Y &2H\"\"6H7I.M &2@\"\"6@7A.A &2d\"\"6d7e.5 &2R\"\"6R7S.) &2N\"\"6N7O&&&#/\"!&,)"),
        peg$decode("%$;).\x89 &2F\"\"6F7G.} &2L\"\"6L7M.q &2X\"\"6X7Y.e &2P\"\"6P7Q.Y &2H\"\"6H7I.M &2@\"\"6@7A.A &2d\"\"6d7e.5 &2R\"\"6R7S.) &2N\"\"6N7O/\x92#0\x8F*;).\x89 &2F\"\"6F7G.} &2L\"\"6L7M.q &2X\"\"6X7Y.e &2P\"\"6P7Q.Y &2H\"\"6H7I.M &2@\"\"6@7A.A &2d\"\"6d7e.5 &2R\"\"6R7S.) &2N\"\"6N7O&&&#/\"!&,)"),
        peg$decode("2T\"\"6T7U.\xE3 &2V\"\"6V7W.\xD7 &2f\"\"6f7g.\xCB &2h\"\"6h7i.\xBF &2:\"\"6:7;.\xB3 &2D\"\"6D7E.\xA7 &22\"\"6273.\x9B &28\"\"6879.\x8F &2j\"\"6j7k.\x83 &;&.} &24\"\"6475.q &2l\"\"6l7m.e &2n\"\"6n7o.Y &26\"\"6677.M &2>\"\"6>7?.A &2p\"\"6p7q.5 &2r\"\"6r7s.) &;'.# &;("),
        peg$decode("%$;).\u012B &2F\"\"6F7G.\u011F &2J\"\"6J7K.\u0113 &2L\"\"6L7M.\u0107 &2X\"\"6X7Y.\xFB &2P\"\"6P7Q.\xEF &2H\"\"6H7I.\xE3 &2@\"\"6@7A.\xD7 &2d\"\"6d7e.\xCB &2R\"\"6R7S.\xBF &2N\"\"6N7O.\xB3 &2T\"\"6T7U.\xA7 &2V\"\"6V7W.\x9B &2f\"\"6f7g.\x8F &2h\"\"6h7i.\x83 &28\"\"6879.w &2j\"\"6j7k.k &;&.e &24\"\"6475.Y &2l\"\"6l7m.M &2n\"\"6n7o.A &26\"\"6677.5 &2p\"\"6p7q.) &2r\"\"6r7s/\u0134#0\u0131*;).\u012B &2F\"\"6F7G.\u011F &2J\"\"6J7K.\u0113 &2L\"\"6L7M.\u0107 &2X\"\"6X7Y.\xFB &2P\"\"6P7Q.\xEF &2H\"\"6H7I.\xE3 &2@\"\"6@7A.\xD7 &2d\"\"6d7e.\xCB &2R\"\"6R7S.\xBF &2N\"\"6N7O.\xB3 &2T\"\"6T7U.\xA7 &2V\"\"6V7W.\x9B &2f\"\"6f7g.\x8F &2h\"\"6h7i.\x83 &28\"\"6879.w &2j\"\"6j7k.k &;&.e &24\"\"6475.Y &2l\"\"6l7m.M &2n\"\"6n7o.A &26\"\"6677.5 &2p\"\"6p7q.) &2r\"\"6r7s&&&#/\"!&,)"),
        peg$decode("%;//?#2P\"\"6P7Q/0$;//'$8#:t# )(#'#(\"'#&'#"),
        peg$decode("%;//?#24\"\"6475/0$;//'$8#:u# )(#'#(\"'#&'#"),
        peg$decode("%;//?#2>\"\"6>7?/0$;//'$8#:v# )(#'#(\"'#&'#"),
        peg$decode("%;//?#2T\"\"6T7U/0$;//'$8#:w# )(#'#(\"'#&'#"),
        peg$decode("%;//?#2V\"\"6V7W/0$;//'$8#:x# )(#'#(\"'#&'#"),
        peg$decode("%2h\"\"6h7i/0#;//'$8\":y\" )(\"'#&'#"),
        peg$decode("%;//6#2f\"\"6f7g/'$8\":z\" )(\"'#&'#"),
        peg$decode("%;//?#2D\"\"6D7E/0$;//'$8#:{# )(#'#(\"'#&'#"),
        peg$decode("%;//?#22\"\"6273/0$;//'$8#:|# )(#'#(\"'#&'#"),
        peg$decode("%;//?#28\"\"6879/0$;//'$8#:}# )(#'#(\"'#&'#"),
        peg$decode("%;//0#;&/'$8\":~\" )(\"'#&'#"),
        peg$decode("%;&/0#;//'$8\":~\" )(\"'#&'#"),
        peg$decode("%;=/T#$;G.) &;K.# &;F0/*;G.) &;K.# &;F&/,$;>/#$+#)(#'#(\"'#&'#"),
        peg$decode("4\x7F\"\"5!7\x80.A &4\x81\"\"5!7\x82.5 &4\x83\"\"5!7\x84.) &;3.# &;."),
        peg$decode("%%;//Q#;&/H$$;J.# &;K0)*;J.# &;K&/,$;&/#$+$)($'#(#'#(\"'#&'#/\"!&,)"),
        peg$decode("%;//]#;&/T$%$;J.# &;K0)*;J.# &;K&/\"!&,)/1$;&/($8$:\x85$!!)($'#(#'#(\"'#&'#"),
        peg$decode(";..G &2L\"\"6L7M.; &4\x86\"\"5!7\x87./ &4\x83\"\"5!7\x84.# &;3"),
        peg$decode("%2j\"\"6j7k/J#4\x88\"\"5!7\x89.5 &4\x8A\"\"5!7\x8B.) &4\x8C\"\"5!7\x8D/#$+\")(\"'#&'#"),
        peg$decode("%;N/M#28\"\"6879/>$;O.\" &\"/0$;S/'$8$:\x8E$ )($'#(#'#(\"'#&'#"),
        peg$decode("%;N/d#28\"\"6879/U$;O.\" &\"/G$;S/>$;^/5$;k.\" &\"/'$8&:\x8F& )(&'#(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%3\x90\"\"5$7\x91.) &3\x92\"\"5#7\x93/' 8!:\x94!! )"),
        peg$decode("%;P/]#%28\"\"6879/,#;R/#$+\")(\"'#&'#.\" &\"/6$2:\"\"6:7;/'$8#:\x95# )(#'#(\"'#&'#"),
        peg$decode("$;+.) &;-.# &;Q/2#0/*;+.) &;-.# &;Q&&&#"),
        peg$decode("2<\"\"6<7=.q &2>\"\"6>7?.e &2@\"\"6@7A.Y &2B\"\"6B7C.M &2D\"\"6D7E.A &22\"\"6273.5 &26\"\"6677.) &24\"\"6475"),
        peg$decode("%$;+._ &;-.Y &2<\"\"6<7=.M &2>\"\"6>7?.A &2@\"\"6@7A.5 &2B\"\"6B7C.) &2D\"\"6D7E0e*;+._ &;-.Y &2<\"\"6<7=.M &2>\"\"6>7?.A &2@\"\"6@7A.5 &2B\"\"6B7C.) &2D\"\"6D7E&/& 8!:\x96! )"),
        peg$decode("%;T/J#%28\"\"6879/,#;]/#$+\")(\"'#&'#.\" &\"/#$+\")(\"'#&'#"),
        peg$decode("%;U./ &;[.) &;W.# &;V/& 8!:\x97! )"),
        peg$decode("%$%;V/2#2J\"\"6J7K/#$+\")(\"'#&'#0<*%;V/2#2J\"\"6J7K/#$+\")(\"'#&'#&/D#;6/;$2J\"\"6J7K.\" &\"/'$8#:\x98# )(#'#(\"'#&'#"),
        peg$decode("$4\x99\"\"5!7\x9A/,#0)*4\x99\"\"5!7\x9A&&&#"),
        peg$decode("%2l\"\"6l7m/?#;X/6$2n\"\"6n7o/'$8#:\x9B# )(#'#(\"'#&'#"),
        peg$decode("%%;Y/\xB3#28\"\"6879/\xA4$;Y/\x9B$28\"\"6879/\x8C$;Y/\x83$28\"\"6879/t$;Y/k$28\"\"6879/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+-)(-'#(,'#(+'#(*'#()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u0790 &%2\x9C\"\"6\x9C7\x9D/\xA4#;Y/\x9B$28\"\"6879/\x8C$;Y/\x83$28\"\"6879/t$;Y/k$28\"\"6879/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+,)(,'#(+'#(*'#()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u06F9 &%2\x9C\"\"6\x9C7\x9D/\x8C#;Y/\x83$28\"\"6879/t$;Y/k$28\"\"6879/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+*)(*'#()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u067A &%2\x9C\"\"6\x9C7\x9D/t#;Y/k$28\"\"6879/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+()(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u0613 &%2\x9C\"\"6\x9C7\x9D/\\#;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+&)(&'#(%'#($'#(#'#(\"'#&'#.\u05C4 &%2\x9C\"\"6\x9C7\x9D/D#;Y/;$28\"\"6879/,$;Z/#$+$)($'#(#'#(\"'#&'#.\u058D &%2\x9C\"\"6\x9C7\x9D/,#;Z/#$+\")(\"'#&'#.\u056E &%2\x9C\"\"6\x9C7\x9D/,#;Y/#$+\")(\"'#&'#.\u054F &%;Y/\x9B#2\x9C\"\"6\x9C7\x9D/\x8C$;Y/\x83$28\"\"6879/t$;Y/k$28\"\"6879/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$++)(+'#(*'#()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u04C7 &%;Y/\xAA#%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\x83$2\x9C\"\"6\x9C7\x9D/t$;Y/k$28\"\"6879/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+*)(*'#()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u0430 &%;Y/\xB9#%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\x92$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/k$2\x9C\"\"6\x9C7\x9D/\\$;Y/S$28\"\"6879/D$;Y/;$28\"\"6879/,$;Z/#$+))()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u038A &%;Y/\xC8#%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xA1$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/z$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/S$2\x9C\"\"6\x9C7\x9D/D$;Y/;$28\"\"6879/,$;Z/#$+()(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u02D5 &%;Y/\xD7#%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xB0$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\x89$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/b$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/;$2\x9C\"\"6\x9C7\x9D/,$;Z/#$+')(''#(&'#(%'#($'#(#'#(\"'#&'#.\u0211 &%;Y/\xFE#%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xD7$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xB0$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\x89$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/b$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/;$2\x9C\"\"6\x9C7\x9D/,$;Y/#$+()(('#(''#(&'#(%'#($'#(#'#(\"'#&'#.\u0126 &%;Y/\u011C#%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xF5$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xCE$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\xA7$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/\x80$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/Y$%28\"\"6879/,#;Y/#$+\")(\"'#&'#.\" &\"/2$2\x9C\"\"6\x9C7\x9D/#$+()(('#(''#(&'#(%'#($'#(#'#(\"'#&'#/& 8!:\x9E! )"),
        peg$decode("%;#/M#;#.\" &\"/?$;#.\" &\"/1$;#.\" &\"/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode("%;Y/;#28\"\"6879/,$;Y/#$+#)(#'#(\"'#&'#.# &;["),
        peg$decode("%;\\/o#2J\"\"6J7K/`$;\\/W$2J\"\"6J7K/H$;\\/?$2J\"\"6J7K/0$;\\/'$8':\x9F' )(''#(&'#(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%2\xA0\"\"6\xA07\xA1/2#4\xA2\"\"5!7\xA3/#$+\")(\"'#&'#.\x98 &%2\xA4\"\"6\xA47\xA5/;#4\xA6\"\"5!7\xA7/,$;!/#$+#)(#'#(\"'#&'#.j &%2\xA8\"\"6\xA87\xA9/5#;!/,$;!/#$+#)(#'#(\"'#&'#.B &%4\xAA\"\"5!7\xAB/,#;!/#$+\")(\"'#&'#.# &;!"),
        peg$decode("%%;!.\" &\"/[#;!.\" &\"/M$;!.\" &\"/?$;!.\" &\"/1$;!.\" &\"/#$+%)(%'#($'#(#'#(\"'#&'#/' 8!:\xAC!! )"),
        peg$decode("$%22\"\"6273/,#;_/#$+\")(\"'#&'#0<*%22\"\"6273/,#;_/#$+\")(\"'#&'#&"),
        peg$decode(";`.A &;a.; &;b.5 &;c./ &;d.) &;e.# &;f"),
        peg$decode("%3\xAD\"\"5*7\xAE/a#3\xAF\"\"5#7\xB0.G &3\xB1\"\"5#7\xB2.; &3\xB3\"\"5$7\xB4./ &3\xB5\"\"5#7\xB6.# &;6/($8\":\xB7\"! )(\"'#&'#"),
        peg$decode("%3\xB8\"\"5%7\xB9/I#3\xBA\"\"5%7\xBB./ &3\xBC\"\"5\"7\xBD.# &;6/($8\":\xBE\"! )(\"'#&'#"),
        peg$decode("%3\xBF\"\"5'7\xC0/1#;\x8F/($8\":\xC1\"! )(\"'#&'#"),
        peg$decode("%3\xC2\"\"5$7\xC3/1#;\xEF/($8\":\xC4\"! )(\"'#&'#"),
        peg$decode("%3\xC5\"\"5&7\xC6/1#;T/($8\":\xC7\"! )(\"'#&'#"),
        peg$decode("%3\xC8\"\"5\"7\xC9/N#%2>\"\"6>7?/,#;6/#$+\")(\"'#&'#.\" &\"/'$8\":\xCA\" )(\"'#&'#"),
        peg$decode("%;g/P#%2>\"\"6>7?/,#;h/#$+\")(\"'#&'#.\" &\"/)$8\":\xCB\"\"! )(\"'#&'#"),
        peg$decode("%$;i/&#0#*;i&&&#/\"!&,)"),
        peg$decode("%$;i/&#0#*;i&&&#/\"!&,)"),
        peg$decode(";j.) &;+.# &;-"),
        peg$decode("2l\"\"6l7m.e &2n\"\"6n7o.Y &24\"\"6475.M &28\"\"6879.A &2<\"\"6<7=.5 &2@\"\"6@7A.) &2B\"\"6B7C"),
        peg$decode("%26\"\"6677/n#;l/e$$%2<\"\"6<7=/,#;l/#$+\")(\"'#&'#0<*%2<\"\"6<7=/,#;l/#$+\")(\"'#&'#&/#$+#)(#'#(\"'#&'#"),
        peg$decode("%;m/A#2>\"\"6>7?/2$;n/)$8#:\xCC#\"\" )(#'#(\"'#&'#"),
        peg$decode("$;o.) &;+.# &;-/2#0/*;o.) &;+.# &;-&&&#"),
        peg$decode("$;o.) &;+.# &;-0/*;o.) &;+.# &;-&"),
        peg$decode("2l\"\"6l7m.e &2n\"\"6n7o.Y &24\"\"6475.M &26\"\"6677.A &28\"\"6879.5 &2@\"\"6@7A.) &2B\"\"6B7C"),
        peg$decode(";\x90.# &;q"),
        peg$decode("%;\x8F/G#;'/>$;r/5$;'/,$;\x83/#$+%)(%'#($'#(#'#(\"'#&'#"),
        peg$decode(";M.# &;s"),
        peg$decode("%;~/E#28\"\"6879/6$;t.# &;w/'$8#:\xCD# )(#'#(\"'#&'#"),
        peg$decode("%;u.# &;v/J#%26\"\"6677/,#;\x82/#$+\")(\"'#&'#.\" &\"/#$+\")(\"'#&'#"),
        peg$decode("%2\xCE\"\"6\xCE7\xCF/:#;\x7F/1$;v.\" &\"/#$+#)(#'#(\"'#&'#"),
        peg$decode("%24\"\"6475/,#;z/#$+\")(\"'#&'#"),
        peg$decode("%;y/3#$;x0#*;x&/#$+\")(\"'#&'#"),
        peg$decode(";*.) &;+.# &;-"),
        peg$decode(";+.\x8F &;-.\x89 &22\"\"6273.} &26\"\"6677.q &28\"\"6879.e &2:\"\"6:7;.Y &2<\"\"6<7=.M &2>\"\"6>7?.A &2@\"\"6@7A.5 &2B\"\"6B7C.) &2D\"\"6D7E"),
        peg$decode("%;{/e#$%24\"\"6475/,#;{/#$+\")(\"'#&'#0<*%24\"\"6475/,#;{/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%$;}0#*;}&/e#$%22\"\"6273/,#;|/#$+\")(\"'#&'#0<*%22\"\"6273/,#;|/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("$;}0#*;}&"),
        peg$decode(";+.w &;-.q &28\"\"6879.e &2:\"\"6:7;.Y &2<\"\"6<7=.M &2>\"\"6>7?.A &2@\"\"6@7A.5 &2B\"\"6B7C.) &2D\"\"6D7E"),
        peg$decode("%%;\"/\x87#$;\".G &;!.A &2@\"\"6@7A.5 &2F\"\"6F7G.) &2J\"\"6J7K0M*;\".G &;!.A &2@\"\"6@7A.5 &2F\"\"6F7G.) &2J\"\"6J7K&/#$+\")(\"'#&'#/& 8!:\xD0! )"),
        peg$decode(";\x80.# &;\x81"),
        peg$decode("%%;O/2#2:\"\"6:7;/#$+\")(\"'#&'#.\" &\"/,#;S/#$+\")(\"'#&'#.\" &\""),
        peg$decode("$;+.\x83 &;-.} &2B\"\"6B7C.q &2D\"\"6D7E.e &22\"\"6273.Y &28\"\"6879.M &2:\"\"6:7;.A &2<\"\"6<7=.5 &2>\"\"6>7?.) &2@\"\"6@7A/\x8C#0\x89*;+.\x83 &;-.} &2B\"\"6B7C.q &2D\"\"6D7E.e &22\"\"6273.Y &28\"\"6879.M &2:\"\"6:7;.A &2<\"\"6<7=.5 &2>\"\"6>7?.) &2@\"\"6@7A&&&#"),
        peg$decode("$;x0#*;x&"),
        peg$decode("%3\x92\"\"5#7\xD1/q#24\"\"6475/b$$;!/&#0#*;!&&&#/L$2J\"\"6J7K/=$$;!/&#0#*;!&&&#/'$8%:\xD2% )(%'#($'#(#'#(\"'#&'#"),
        peg$decode("2\xD3\"\"6\xD37\xD4"),
        peg$decode("2\xD5\"\"6\xD57\xD6"),
        peg$decode("2\xD7\"\"6\xD77\xD8"),
        peg$decode("2\xD9\"\"6\xD97\xDA"),
        peg$decode("2\xDB\"\"6\xDB7\xDC"),
        peg$decode("2\xDD\"\"6\xDD7\xDE"),
        peg$decode("2\xDF\"\"6\xDF7\xE0"),
        peg$decode("2\xE1\"\"6\xE17\xE2"),
        peg$decode("2\xE3\"\"6\xE37\xE4"),
        peg$decode("2\xE5\"\"6\xE57\xE6"),
        peg$decode("2\xE7\"\"6\xE77\xE8"),
        peg$decode("%;\x84.Y &;\x85.S &;\x87.M &;\x88.G &;\x89.A &;\x8A.; &;\x8B.5 &;\x8E./ &;\x8C.) &;\x8D.# &;6/& 8!:\xE9! )"),
        peg$decode("%;\x83/G#;'/>$;\x91/5$;'/,$;\x93/#$+%)(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%;\x92/' 8!:\xEA!! )"),
        peg$decode("%;!/5#;!/,$;!/#$+#)(#'#(\"'#&'#"),
        peg$decode("%$;*.A &;+.; &;-.5 &;3./ &;4.) &;'.# &;(0G*;*.A &;+.; &;-.5 &;3./ &;4.) &;'.# &;(&/& 8!:\xEB! )"),
        peg$decode("%;\xB5/Y#$%;A/,#;\xB5/#$+\")(\"'#&'#06*%;A/,#;\xB5/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%;9/N#%2:\"\"6:7;/,#;9/#$+\")(\"'#&'#.\" &\"/'$8\":\xEC\" )(\"'#&'#"),
        peg$decode("%;:.c &%;\x97/Y#$%;A/,#;\x97/#$+\")(\"'#&'#06*%;A/,#;\x97/#$+\")(\"'#&'#&/#$+\")(\"'#&'#/& 8!:\xED! )"),
        peg$decode("%;L.# &;\x98/]#$%;B/,#;\x9A/#$+\")(\"'#&'#06*%;B/,#;\x9A/#$+\")(\"'#&'#&/'$8\":\xEE\" )(\"'#&'#"),
        peg$decode("%;\x99.\" &\"/>#;@/5$;M/,$;?/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode("%%;6/Y#$%;./,#;6/#$+\")(\"'#&'#06*%;./,#;6/#$+\")(\"'#&'#&/#$+\")(\"'#&'#.# &;H/' 8!:\xEF!! )"),
        peg$decode(";\x9B.) &;\x9C.# &;\x9F"),
        peg$decode("%3\xF0\"\"5!7\xF1/:#;</1$;\x9E/($8#:\xF2#! )(#'#(\"'#&'#"),
        peg$decode("%3\xF3\"\"5'7\xF4/:#;</1$;\x9D/($8#:\xF5#! )(#'#(\"'#&'#"),
        peg$decode("%$;!/&#0#*;!&&&#/' 8!:\xF6!! )"),
        peg$decode("%2\xF7\"\"6\xF77\xF8/o#%2J\"\"6J7K/M#;!.\" &\"/?$;!.\" &\"/1$;!.\" &\"/#$+$)($'#(#'#(\"'#&'#.\" &\"/'$8\":\xF9\" )(\"'#&'#"),
        peg$decode("%;6/J#%;</,#;\xA0/#$+\")(\"'#&'#.\" &\"/)$8\":\xFA\"\"! )(\"'#&'#"),
        peg$decode(";6.) &;T.# &;H"),
        peg$decode("%;\xA2/Y#$%;B/,#;\xA3/#$+\")(\"'#&'#06*%;B/,#;\xA3/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%3\xFB\"\"5&7\xFC.G &3\xFD\"\"5'7\xFE.; &3\xFF\"\"5$7\u0100./ &3\u0101\"\"5%7\u0102.# &;6/& 8!:\u0103! )"),
        peg$decode(";\xA4.# &;\x9F"),
        peg$decode("%3\u0104\"\"5(7\u0105/M#;</D$3\u0106\"\"5(7\u0107./ &3\u0108\"\"5(7\u0109.# &;6/#$+#)(#'#(\"'#&'#"),
        peg$decode("%;6/Y#$%;A/,#;6/#$+\")(\"'#&'#06*%;A/,#;6/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%$;!/&#0#*;!&&&#/' 8!:\u010A!! )"),
        peg$decode("%;\xA8/& 8!:\u010B! )"),
        peg$decode("%;\xA9/k#;;/b$;\xAE/Y$$%;B/,#;\xAF/#$+\")(\"'#&'#06*%;B/,#;\xAF/#$+\")(\"'#&'#&/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode(";\xAA.# &;\xAB"),
        peg$decode("3\u010C\"\"5$7\u010D.S &3\u010E\"\"5%7\u010F.G &3\u0110\"\"5%7\u0111.; &3\u0112\"\"5%7\u0113./ &3\u0114\"\"5+7\u0115.# &;\xAC"),
        peg$decode("3\u0116\"\"5'7\u0117./ &3\u0118\"\"5)7\u0119.# &;\xAC"),
        peg$decode(";6.# &;\xAD"),
        peg$decode("%3\u011A\"\"5\"7\u011B/,#;6/#$+\")(\"'#&'#"),
        peg$decode(";\xAC.# &;6"),
        peg$decode("%;6/5#;</,$;\xB0/#$+#)(#'#(\"'#&'#"),
        peg$decode(";6.# &;H"),
        peg$decode("%;\xB2/5#;./,$;\x8F/#$+#)(#'#(\"'#&'#"),
        peg$decode("%$;!/&#0#*;!&&&#/' 8!:\u011C!! )"),
        peg$decode("%;\x9D/' 8!:\u011D!! )"),
        peg$decode("%;\xB5/^#$%;B/,#;\x9F/#$+\")(\"'#&'#06*%;B/,#;\x9F/#$+\")(\"'#&'#&/($8\":\u011E\"!!)(\"'#&'#"),
        peg$decode("%%;7/e#$%2J\"\"6J7K/,#;7/#$+\")(\"'#&'#0<*%2J\"\"6J7K/,#;7/#$+\")(\"'#&'#&/#$+\")(\"'#&'#/\"!&,)"),
        peg$decode("%;L.# &;\x98/]#$%;B/,#;\xB7/#$+\")(\"'#&'#06*%;B/,#;\xB7/#$+\")(\"'#&'#&/'$8\":\u011F\" )(\"'#&'#"),
        peg$decode(";\xB8.# &;\x9F"),
        peg$decode("%3\u0120\"\"5#7\u0121/:#;</1$;6/($8#:\u0122#! )(#'#(\"'#&'#"),
        peg$decode("%$;!/&#0#*;!&&&#/' 8!:\u0123!! )"),
        peg$decode("%;\x9D/' 8!:\u0124!! )"),
        peg$decode("%$;\x990#*;\x99&/x#;@/o$;M/f$;?/]$$%;B/,#;\x9F/#$+\")(\"'#&'#06*%;B/,#;\x9F/#$+\")(\"'#&'#&/'$8%:\u0125% )(%'#($'#(#'#(\"'#&'#"),
        peg$decode(";\xBD"),
        peg$decode("%3\u0126\"\"5&7\u0127/k#;./b$;\xC0/Y$$%;A/,#;\xC0/#$+\")(\"'#&'#06*%;A/,#;\xC0/#$+\")(\"'#&'#&/#$+$)($'#(#'#(\"'#&'#.# &;\xBE"),
        peg$decode("%;6/k#;./b$;\xBF/Y$$%;A/,#;\xBF/#$+\")(\"'#&'#06*%;A/,#;\xBF/#$+\")(\"'#&'#&/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode("%;6/;#;</2$;6.# &;H/#$+#)(#'#(\"'#&'#"),
        peg$decode(";\xC1.G &;\xC3.A &;\xC5.; &;\xC7.5 &;\xC8./ &;\xC9.) &;\xCA.# &;\xBF"),
        peg$decode("%3\u0128\"\"5%7\u0129/5#;</,$;\xC2/#$+#)(#'#(\"'#&'#"),
        peg$decode("%;I/' 8!:\u012A!! )"),
        peg$decode("%3\u012B\"\"5&7\u012C/\x97#;</\x8E$;D/\x85$;\xC4/|$$%$;'/&#0#*;'&&&#/,#;\xC4/#$+\")(\"'#&'#0C*%$;'/&#0#*;'&&&#/,#;\xC4/#$+\")(\"'#&'#&/,$;E/#$+&)(&'#(%'#($'#(#'#(\"'#&'#"),
        peg$decode(";s.# &;v"),
        peg$decode("%3\u012D\"\"5%7\u012E/5#;</,$;\xC6/#$+#)(#'#(\"'#&'#"),
        peg$decode("%;I/' 8!:\u012F!! )"),
        peg$decode("%3\u0130\"\"5&7\u0131/:#;</1$;I/($8#:\u0132#! )(#'#(\"'#&'#"),
        peg$decode("%3\u0133\"\"5%7\u0134/]#;</T$%3\u0135\"\"5$7\u0136/& 8!:\u0137! ).4 &%3\u0138\"\"5%7\u0139/& 8!:\u013A! )/#$+#)(#'#(\"'#&'#"),
        peg$decode("%3\u013B\"\"5)7\u013C/R#;</I$3\u013D\"\"5#7\u013E./ &3\u013F\"\"5(7\u0140.# &;6/($8#:\u0141#! )(#'#(\"'#&'#"),
        peg$decode("%3\u0142\"\"5#7\u0143/\x93#;</\x8A$;D/\x81$%;\xCB/e#$%2D\"\"6D7E/,#;\xCB/#$+\")(\"'#&'#0<*%2D\"\"6D7E/,#;\xCB/#$+\")(\"'#&'#&/#$+\")(\"'#&'#/,$;E/#$+%)(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%3\u0144\"\"5(7\u0145./ &3\u0146\"\"5$7\u0147.# &;6/' 8!:\u0148!! )"),
        peg$decode("%;6/Y#$%;A/,#;6/#$+\")(\"'#&'#06*%;A/,#;6/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%;\xCE/G#;./>$;\xCE/5$;./,$;\x8F/#$+%)(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%$;!/&#0#*;!&&&#/' 8!:\u0149!! )"),
        peg$decode("%;\xD0/]#$%;A/,#;\xD0/#$+\")(\"'#&'#06*%;A/,#;\xD0/#$+\")(\"'#&'#&/'$8\":\u014A\" )(\"'#&'#"),
        peg$decode("%;\x98/]#$%;B/,#;\x9F/#$+\")(\"'#&'#06*%;B/,#;\x9F/#$+\")(\"'#&'#&/'$8\":\u014B\" )(\"'#&'#"),
        peg$decode("%;L.O &;\x98.I &%;@.\" &\"/:#;s/1$;?.\" &\"/#$+#)(#'#(\"'#&'#/]#$%;B/,#;\x9F/#$+\")(\"'#&'#06*%;B/,#;\x9F/#$+\")(\"'#&'#&/'$8\":\u014C\" )(\"'#&'#"),
        peg$decode("%;\xD3/]#$%;B/,#;\xD4/#$+\")(\"'#&'#06*%;B/,#;\xD4/#$+\")(\"'#&'#&/'$8\":\u014D\" )(\"'#&'#"),
        peg$decode("%;\x95/& 8!:\u014E! )"),
        peg$decode("%3\u014F\"\"5(7\u0150/:#;</1$;6/($8#:\u0151#! )(#'#(\"'#&'#.g &%3\u0152\"\"5&7\u0153/:#;</1$;6/($8#:\u0154#! )(#'#(\"'#&'#.: &%3\u0155\"\"5*7\u0156/& 8!:\u0157! ).# &;\x9F"),
        peg$decode("%%;6/k#$%;A/2#;6/)$8\":\u0158\"\"$ )(\"'#&'#0<*%;A/2#;6/)$8\":\u0158\"\"$ )(\"'#&'#&/)$8\":\u0159\"\"! )(\"'#&'#.\" &\"/' 8!:\u015A!! )"),
        peg$decode("%;\xD7/Y#$%;A/,#;\xD7/#$+\")(\"'#&'#06*%;A/,#;\xD7/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%;\x98/Y#$%;B/,#;\x9F/#$+\")(\"'#&'#06*%;B/,#;\x9F/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%$;!/&#0#*;!&&&#/' 8!:\u015B!! )"),
        peg$decode("%;\xDA/Y#$%;B/,#;\xDB/#$+\")(\"'#&'#06*%;B/,#;\xDB/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%3\u015C\"\"5&7\u015D.; &3\u015E\"\"5'7\u015F./ &3\u0160\"\"5*7\u0161.# &;6/& 8!:\u0162! )"),
        peg$decode("%3\u0163\"\"5&7\u0164/:#;</1$;\xDC/($8#:\u0165#! )(#'#(\"'#&'#.} &%3\xF3\"\"5'7\xF4/:#;</1$;\x9D/($8#:\u0166#! )(#'#(\"'#&'#.P &%3\u0167\"\"5+7\u0168/:#;</1$;\x9D/($8#:\u0169#! )(#'#(\"'#&'#.# &;\x9F"),
        peg$decode("3\u016A\"\"5+7\u016B.k &3\u016C\"\"5)7\u016D._ &3\u016E\"\"5(7\u016F.S &3\u0170\"\"5'7\u0171.G &3\u0172\"\"5&7\u0173.; &3\u0174\"\"5*7\u0175./ &3\u0176\"\"5)7\u0177.# &;6"),
        peg$decode(";1.\" &\""),
        peg$decode("%%;6/k#$%;A/2#;6/)$8\":\u0158\"\"$ )(\"'#&'#0<*%;A/2#;6/)$8\":\u0158\"\"$ )(\"'#&'#&/)$8\":\u0159\"\"! )(\"'#&'#.\" &\"/' 8!:\u0178!! )"),
        peg$decode("%;L.# &;\x98/]#$%;B/,#;\xE0/#$+\")(\"'#&'#06*%;B/,#;\xE0/#$+\")(\"'#&'#&/'$8\":\u0179\" )(\"'#&'#"),
        peg$decode(";\xB8.# &;\x9F"),
        peg$decode("%;\xE2/Y#$%;A/,#;\xE2/#$+\")(\"'#&'#06*%;A/,#;\xE2/#$+\")(\"'#&'#&/#$+\")(\"'#&'#"),
        peg$decode("%;\xE9/k#;./b$;\xEC/Y$$%;B/,#;\xE3/#$+\")(\"'#&'#06*%;B/,#;\xE3/#$+\")(\"'#&'#&/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode(";\xE4.; &;\xE5.5 &;\xE6./ &;\xE7.) &;\xE8.# &;\x9F"),
        peg$decode("%3\u017A\"\"5#7\u017B/:#;</1$;\xEF/($8#:\u017C#! )(#'#(\"'#&'#"),
        peg$decode("%3\u017D\"\"5%7\u017E/:#;</1$;T/($8#:\u017F#! )(#'#(\"'#&'#"),
        peg$decode("%3\u0180\"\"5(7\u0181/F#;</=$;[.) &;X.# &;W/($8#:\u0182#! )(#'#(\"'#&'#"),
        peg$decode("%3\u0183\"\"5&7\u0184/:#;</1$;6/($8#:\u0185#! )(#'#(\"'#&'#"),
        peg$decode("%3\u0186\"\"5%7\u0187/A#;</8$$;!0#*;!&/($8#:\u0188#! )(#'#(\"'#&'#"),
        peg$decode("%;\xEA/G#;;/>$;6/5$;;/,$;\xEB/#$+%)(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%3\x92\"\"5#7\xD1.# &;6/' 8!:\u0189!! )"),
        peg$decode("%3\xAF\"\"5#7\u018A.G &3\xB1\"\"5#7\u018B.; &3\xB5\"\"5#7\u018C./ &3\xB3\"\"5$7\u018D.# &;6/' 8!:\u018E!! )"),
        peg$decode("%;\xED/D#%;C/,#;\xEE/#$+\")(\"'#&'#.\" &\"/#$+\")(\"'#&'#"),
        peg$decode("%;U.) &;[.# &;W/& 8!:\u018F! )"),
        peg$decode("%%;!.\" &\"/[#;!.\" &\"/M$;!.\" &\"/?$;!.\" &\"/1$;!.\" &\"/#$+%)(%'#($'#(#'#(\"'#&'#/' 8!:\u0190!! )"),
        peg$decode("%%;!/?#;!.\" &\"/1$;!.\" &\"/#$+#)(#'#(\"'#&'#/' 8!:\u0191!! )"),
        peg$decode(";\xBD"),
        peg$decode("%;\x9D/^#$%;B/,#;\xF2/#$+\")(\"'#&'#06*%;B/,#;\xF2/#$+\")(\"'#&'#&/($8\":\u0192\"!!)(\"'#&'#"),
        peg$decode(";\xF3.# &;\x9F"),
        peg$decode("%2\u0193\"\"6\u01937\u0194/L#;</C$2\u0195\"\"6\u01957\u0196.) &2\u0197\"\"6\u01977\u0198/($8#:\u0199#! )(#'#(\"'#&'#"),
        peg$decode("%;\x9D/^#$%;B/,#;\x9F/#$+\")(\"'#&'#06*%;B/,#;\x9F/#$+\")(\"'#&'#&/($8\":\u019A\"!!)(\"'#&'#"),
        peg$decode("%;6/5#;0/,$;\xF6/#$+#)(#'#(\"'#&'#"),
        peg$decode("$;2.) &;4.# &;.0/*;2.) &;4.# &;.&"),
        peg$decode("$;%0#*;%&"),
        peg$decode("%;\xF9/;#28\"\"6879/,$;\xFA/#$+#)(#'#(\"'#&'#"),
        peg$decode("%3\u019B\"\"5%7\u019C.) &3\u019D\"\"5$7\u019E/' 8!:\u019F!! )"),
        peg$decode("%;\xFB/J#%28\"\"6879/,#;]/#$+\")(\"'#&'#.\" &\"/#$+\")(\"'#&'#"),
        peg$decode("%;[.) &;W.# &;\x81/' 8!:\u01A0!! )"),
        peg$decode(";\".S &;!.M &2F\"\"6F7G.A &2J\"\"6J7K.5 &2H\"\"6H7I.) &2N\"\"6N7O"),
        peg$decode("2L\"\"6L7M.\x95 &2B\"\"6B7C.\x89 &2<\"\"6<7=.} &2R\"\"6R7S.q &2T\"\"6T7U.e &2V\"\"6V7W.Y &2P\"\"6P7Q.M &2@\"\"6@7A.A &2D\"\"6D7E.5 &22\"\"6273.) &2>\"\"6>7?"),
        peg$decode("%;\xFF/b#28\"\"6879/S$;\xFA/J$%2\u01A1\"\"6\u01A17\u01A2/,#;\xEB/#$+\")(\"'#&'#.\" &\"/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode("%3\u01A3\"\"5%7\u01A4.) &3\u01A5\"\"5$7\u01A6/' 8!:\u019F!! )"),
        peg$decode("%3\xAF\"\"5#7\xB0.6 &3\xB1\"\"5#7\xB2.* &$;+0#*;+&/' 8!:\u01A7!! )"),
        peg$decode("%;\u0103/\x87#2F\"\"6F7G/x$;\u0102/o$2F\"\"6F7G/`$;\u0102/W$2F\"\"6F7G/H$;\u0102/?$2F\"\"6F7G/0$;\u0104/'$8):\u01A8) )()'#(('#(''#(&'#(%'#($'#(#'#(\"'#&'#"),
        peg$decode("%;#/>#;#/5$;#/,$;#/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode("%;\u0102/,#;\u0102/#$+\")(\"'#&'#"),
        peg$decode("%;\u0102/5#;\u0102/,$;\u0102/#$+#)(#'#(\"'#&'#"),
        peg$decode("%;p/T#$;l0#*;l&/D$%; /,#;\xF7/#$+\")(\"'#&'#.\" &\"/#$+#)(#'#(\"'#&'#"),
        peg$decode("%2\u01A9\"\"6\u01A97\u01AA.) &2\u01AB\"\"6\u01AB7\u01AC/w#;0/n$;\u0107/e$$%;B/2#;\u0108.# &;\x9F/#$+\")(\"'#&'#0<*%;B/2#;\u0108.# &;\x9F/#$+\")(\"'#&'#&/#$+$)($'#(#'#(\"'#&'#"),
        peg$decode(";\x98.# &;L"),
        peg$decode("%2\u01AD\"\"6\u01AD7\u01AE/5#;</,$;\u0109/#$+#)(#'#(\"'#&'#"),
        peg$decode("%;D/S#;,/J$2:\"\"6:7;/;$;,.# &;T/,$;E/#$+%)(%'#($'#(#'#(\"'#&'#")
    ];
    let peg$currPos = 0;
    let peg$savedPos = 0;
    const peg$posDetailsCache = [{ line: 1, column: 1 }];
    let peg$maxFailPos = 0;
    let peg$maxFailExpected = [];
    let peg$silentFails = 0;
    let peg$result;
    if (options.startRule !== undefined) {
        if (!(options.startRule in peg$startRuleIndices)) {
            throw new Error("Can't start parsing from rule \"" + options.startRule + "\".");
        }
        peg$startRuleIndex = peg$startRuleIndices[options.startRule];
    }
    function text() {
        return input.substring(peg$savedPos, peg$currPos);
    }
    function location() {
        return peg$computeLocation(peg$savedPos, peg$currPos);
    }
    function expected(description, location1) {
        location1 = location1 !== undefined
            ? location1
            : peg$computeLocation(peg$savedPos, peg$currPos);
        throw peg$buildStructuredError([peg$otherExpectation(description)], input.substring(peg$savedPos, peg$currPos), location1);
    }
    function error(message, location1) {
        location1 = location1 !== undefined
            ? location1
            : peg$computeLocation(peg$savedPos, peg$currPos);
        throw peg$buildSimpleError(message, location1);
    }
    function peg$literalExpectation(text1, ignoreCase) {
        return { type: "literal", text: text1, ignoreCase: ignoreCase };
    }
    function peg$classExpectation(parts, inverted, ignoreCase) {
        return { type: "class", parts: parts, inverted: inverted, ignoreCase: ignoreCase };
    }
    function peg$anyExpectation() {
        return { type: "any" };
    }
    function peg$endExpectation() {
        return { type: "end" };
    }
    function peg$otherExpectation(description) {
        return { type: "other", description: description };
    }
    function peg$computePosDetails(pos) {
        let details = peg$posDetailsCache[pos];
        let p;
        if (details) {
            return details;
        }
        else {
            p = pos - 1;
            while (!peg$posDetailsCache[p]) {
                p--;
            }
            details = peg$posDetailsCache[p];
            details = {
                line: details.line,
                column: details.column
            };
            while (p < pos) {
                if (input.charCodeAt(p) === 10) {
                    details.line++;
                    details.column = 1;
                }
                else {
                    details.column++;
                }
                p++;
            }
            peg$posDetailsCache[pos] = details;
            return details;
        }
    }
    function peg$computeLocation(startPos, endPos) {
        const startPosDetails = peg$computePosDetails(startPos);
        const endPosDetails = peg$computePosDetails(endPos);
        return {
            start: {
                offset: startPos,
                line: startPosDetails.line,
                column: startPosDetails.column
            },
            end: {
                offset: endPos,
                line: endPosDetails.line,
                column: endPosDetails.column
            }
        };
    }
    function peg$fail(expected1) {
        if (peg$currPos < peg$maxFailPos) {
            return;
        }
        if (peg$currPos > peg$maxFailPos) {
            peg$maxFailPos = peg$currPos;
            peg$maxFailExpected = [];
        }
        peg$maxFailExpected.push(expected1);
    }
    function peg$buildSimpleError(message, location1) {
        return new SyntaxError(message, [], "", location1);
    }
    function peg$buildStructuredError(expected1, found, location1) {
        return new SyntaxError(SyntaxError.buildMessage(expected1, found), expected1, found, location1);
    }
    function peg$decode(s) {
        return s.split("").map((ch) => ch.charCodeAt(0) - 32);
    }
    function peg$parseRule(index) {
        const bc = peg$bytecode[index];
        let ip = 0;
        const ips = [];
        let end = bc.length;
        const ends = [];
        const stack = [];
        let params;
        while (true) {
            while (ip < end) {
                switch (bc[ip]) {
                    case 0:
                        stack.push(peg$consts[bc[ip + 1]]);
                        ip += 2;
                        break;
                    case 1:
                        stack.push(undefined);
                        ip++;
                        break;
                    case 2:
                        stack.push(null);
                        ip++;
                        break;
                    case 3:
                        stack.push(peg$FAILED);
                        ip++;
                        break;
                    case 4:
                        stack.push([]);
                        ip++;
                        break;
                    case 5:
                        stack.push(peg$currPos);
                        ip++;
                        break;
                    case 6:
                        stack.pop();
                        ip++;
                        break;
                    case 7:
                        peg$currPos = stack.pop();
                        ip++;
                        break;
                    case 8:
                        stack.length -= bc[ip + 1];
                        ip += 2;
                        break;
                    case 9:
                        stack.splice(-2, 1);
                        ip++;
                        break;
                    case 10:
                        stack[stack.length - 2].push(stack.pop());
                        ip++;
                        break;
                    case 11:
                        stack.push(stack.splice(stack.length - bc[ip + 1], bc[ip + 1]));
                        ip += 2;
                        break;
                    case 12:
                        stack.push(input.substring(stack.pop(), peg$currPos));
                        ip++;
                        break;
                    case 13:
                        ends.push(end);
                        ips.push(ip + 3 + bc[ip + 1] + bc[ip + 2]);
                        if (stack[stack.length - 1]) {
                            end = ip + 3 + bc[ip + 1];
                            ip += 3;
                        }
                        else {
                            end = ip + 3 + bc[ip + 1] + bc[ip + 2];
                            ip += 3 + bc[ip + 1];
                        }
                        break;
                    case 14:
                        ends.push(end);
                        ips.push(ip + 3 + bc[ip + 1] + bc[ip + 2]);
                        if (stack[stack.length - 1] === peg$FAILED) {
                            end = ip + 3 + bc[ip + 1];
                            ip += 3;
                        }
                        else {
                            end = ip + 3 + bc[ip + 1] + bc[ip + 2];
                            ip += 3 + bc[ip + 1];
                        }
                        break;
                    case 15:
                        ends.push(end);
                        ips.push(ip + 3 + bc[ip + 1] + bc[ip + 2]);
                        if (stack[stack.length - 1] !== peg$FAILED) {
                            end = ip + 3 + bc[ip + 1];
                            ip += 3;
                        }
                        else {
                            end = ip + 3 + bc[ip + 1] + bc[ip + 2];
                            ip += 3 + bc[ip + 1];
                        }
                        break;
                    case 16:
                        if (stack[stack.length - 1] !== peg$FAILED) {
                            ends.push(end);
                            ips.push(ip);
                            end = ip + 2 + bc[ip + 1];
                            ip += 2;
                        }
                        else {
                            ip += 2 + bc[ip + 1];
                        }
                        break;
                    case 17:
                        ends.push(end);
                        ips.push(ip + 3 + bc[ip + 1] + bc[ip + 2]);
                        if (input.length > peg$currPos) {
                            end = ip + 3 + bc[ip + 1];
                            ip += 3;
                        }
                        else {
                            end = ip + 3 + bc[ip + 1] + bc[ip + 2];
                            ip += 3 + bc[ip + 1];
                        }
                        break;
                    case 18:
                        ends.push(end);
                        ips.push(ip + 4 + bc[ip + 2] + bc[ip + 3]);
                        if (input.substr(peg$currPos, peg$consts[bc[ip + 1]].length) === peg$consts[bc[ip + 1]]) {
                            end = ip + 4 + bc[ip + 2];
                            ip += 4;
                        }
                        else {
                            end = ip + 4 + bc[ip + 2] + bc[ip + 3];
                            ip += 4 + bc[ip + 2];
                        }
                        break;
                    case 19:
                        ends.push(end);
                        ips.push(ip + 4 + bc[ip + 2] + bc[ip + 3]);
                        if (input.substr(peg$currPos, peg$consts[bc[ip + 1]].length).toLowerCase() === peg$consts[bc[ip + 1]]) {
                            end = ip + 4 + bc[ip + 2];
                            ip += 4;
                        }
                        else {
                            end = ip + 4 + bc[ip + 2] + bc[ip + 3];
                            ip += 4 + bc[ip + 2];
                        }
                        break;
                    case 20:
                        ends.push(end);
                        ips.push(ip + 4 + bc[ip + 2] + bc[ip + 3]);
                        if (peg$consts[bc[ip + 1]].test(input.charAt(peg$currPos))) {
                            end = ip + 4 + bc[ip + 2];
                            ip += 4;
                        }
                        else {
                            end = ip + 4 + bc[ip + 2] + bc[ip + 3];
                            ip += 4 + bc[ip + 2];
                        }
                        break;
                    case 21:
                        stack.push(input.substr(peg$currPos, bc[ip + 1]));
                        peg$currPos += bc[ip + 1];
                        ip += 2;
                        break;
                    case 22:
                        stack.push(peg$consts[bc[ip + 1]]);
                        peg$currPos += peg$consts[bc[ip + 1]].length;
                        ip += 2;
                        break;
                    case 23:
                        stack.push(peg$FAILED);
                        if (peg$silentFails === 0) {
                            peg$fail(peg$consts[bc[ip + 1]]);
                        }
                        ip += 2;
                        break;
                    case 24:
                        peg$savedPos = stack[stack.length - 1 - bc[ip + 1]];
                        ip += 2;
                        break;
                    case 25:
                        peg$savedPos = peg$currPos;
                        ip++;
                        break;
                    case 26:
                        params = bc.slice(ip + 4, ip + 4 + bc[ip + 3])
                            .map(function (p) { return stack[stack.length - 1 - p]; });
                        stack.splice(stack.length - bc[ip + 2], bc[ip + 2], peg$consts[bc[ip + 1]].apply(null, params));
                        ip += 4 + bc[ip + 3];
                        break;
                    case 27:
                        stack.push(peg$parseRule(bc[ip + 1]));
                        ip += 2;
                        break;
                    case 28:
                        peg$silentFails++;
                        ip++;
                        break;
                    case 29:
                        peg$silentFails--;
                        ip++;
                        break;
                    default:
                        throw new Error("Invalid opcode: " + bc[ip] + ".");
                }
            }
            if (ends.length > 0) {
                end = ends.pop();
                ip = ips.pop();
            }
            else {
                break;
            }
        }
        return stack[0];
    }
    options.data = {}; // Object to which header attributes will be assigned during parsing
    function list(head, tail) {
        return [head].concat(tail);
    }
    peg$result = peg$parseRule(peg$startRuleIndex);
    if (peg$result !== peg$FAILED && peg$currPos === input.length) {
        return peg$result;
    }
    else {
        if (peg$result !== peg$FAILED && peg$currPos < input.length) {
            peg$fail(peg$endExpectation());
        }
        throw peg$buildStructuredError(peg$maxFailExpected, peg$maxFailPos < input.length ? input.charAt(peg$maxFailPos) : null, peg$maxFailPos < input.length
            ? peg$computeLocation(peg$maxFailPos, peg$maxFailPos + 1)
            : peg$computeLocation(peg$maxFailPos, peg$maxFailPos));
    }
}
export const parse = peg$parse;
