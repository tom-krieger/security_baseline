# @summary 
#    Create summary reporting
#
# Call function for summary report create.
#
# @param reports
#    Select which reports to produce.
#
# @param summary_report
#    File to write a summary report yaml report
#
# @example
#   include security_baseline::summary_result
#
# @api private
class security_baseline::summary_result (
  Enum['summary', 'details', 'both'] $reports = 'both',
  String $summary_report                      = '/opt/puppetlabs/facter/facts.d/security_baseline_summary.yaml',
) {
  if($reports == 'both' or $reports == 'summary') {
    $summary = security_baseline::summary("/tmp/security_baseline_summary_${::hostname}.txt", true)

    if empty($summary) {
      echo { 'no-summary-data':
        message  => 'no summary data',
        loglevel => 'warning',
        withpath => false,
      }
    } else {
      file { $summary_report:
        ensure  => file,
        content => epp('security_baseline/summary_report.epp', {
          compliant          => $summary['ok'],
          failed             => $summary['fail'],
          unknown            => $summary['unknown'],
          notchecked         => $summary['notchecked'],
          compliant_count    => $summary['summary']['count_ok'],
          failed_count       => $summary['summary']['count_fail'],
          unknown_count      => $summary['summary']['count_unknown'],
          notchecked_count   => $summary['summary']['count_notchecked'],
          compliant_percent  => $summary['summary']['percent_ok'],
          failed_percent     => $summary['summary']['percent_fail'],
          unknown_percent    => $summary['summary']['percent_unknown'],
          notchecked_percent => $summary['summary']['percent_notchecked',]
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }
    }
  }
}
