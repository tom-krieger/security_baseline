# @summary 
#    Initialize summary reporting
#
# Call function for summary report initialize.
#
# @param reports
#    Select which reports to produce.
#
# @example
#   include security_baseline::summary_init
#
# @api private
class security_baseline::summary_init (
  Enum['summary', 'details', 'both'] $reports = 'both',
) {
  if($reports == 'both' or $reports == 'summary') {
    security_baseline::init("/tmp/security_baseline_summary_${::hostname}.txt", true)
  } else {
    echo { 'summary-no-init':
      message  => 'summary not initialized',
      loglevel => 'warning',
      withpath => false,
    }
  }
}
