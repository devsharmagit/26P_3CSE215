# Compatibility shim: restores the Zeek <= 7.0 standalone SumStats epoch behaviour that scan.zeek relies on.
#
# Since Zeek 7.1 (still in 9.0.0) base/frameworks/sumstats/non-cluster.zeek::do_finish_epoch() starts with
#     if ( ss$name !in result_store || ! ss?$epoch_result ) return;
# so a SumStat WITHOUT an $epoch_result callback (both of scan.zeek's SumStats) is never reset and its next
# epoch is never scheduled: the "5min"/"60sec" epoch silently becomes one epoch for the whole run. In Zeek
# v6.0.9 (the release scan.zeek comes from) finish_epoch() reset such a SumStat and rescheduled the next
# epoch. This handler does exactly that for SumStats without $epoch_result only; SumStats that do have
# $epoch_result are left to Zeek 9's own code. No threshold, interval or detection logic is changed.
@load base/frameworks/sumstats

module SumStats;

event SumStats::finish_epoch(ss: SumStat) &priority=-10
	{
	if ( zeek_is_terminating() || ss?$epoch_result )
		return;

	if ( ss$name in result_store )
		reset(ss);

	if ( ss$epoch != 0secs )
		schedule ss$epoch { SumStats::finish_epoch(ss) };
	}
