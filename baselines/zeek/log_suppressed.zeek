# Observation only: records every Scan::* notice that the notice framework suppressed
# (Zeek does not log suppressed notices by itself). It does not change what is detected or logged
# in notice.log. ts is network_time() at the moment the suppressed NOTICE() call happened.
module ScanSuppressed;

export {
	redef enum Log::ID += { LOG };
	type Info: record {
		ts:   time   &log;
		note: string &log;
		src:  addr   &log &optional;
		dst:  addr   &log &optional;
		msg:  string &log &optional;
	};
}

event zeek_init()
	{
	Log::create_stream(ScanSuppressed::LOG, [$columns=Info, $path="scan_suppressed"]);
	}

event Notice::suppressed(n: Notice::Info)
	{
	if ( n$note != Scan::Port_Scan && n$note != Scan::Address_Scan )
		return;
	local r = Info($ts=network_time(), $note=cat(n$note));
	if ( n?$src ) r$src = n$src;
	if ( n?$dst ) r$dst = n$dst;
	if ( n?$msg ) r$msg = n$msg;
	Log::write(ScanSuppressed::LOG, r);
	}
