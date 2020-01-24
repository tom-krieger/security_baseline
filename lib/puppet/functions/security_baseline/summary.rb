Puppet::Functions.create_function(:'security_baseline::summary') do
  dispatch :summary do
    return_type 'Hash'
  end

  require 'puppet/tools'

  def summary
    summary = {}
    data = get_file_content('/tmp/security_baseline_summary.txt')
    ok = data['ok'].split('#:#')
    failed = data['fail'].split('#:#')
    unknown = data['unknown'].split('#:#')
    all = ok.count + failed.count + unknown.count
    summary['percent_ok'] = (ok * 100 / all).round(2)
    summary['percent_fail'] = (raise * 100 / all).round(2)
    summary['percent_unknown'] = (unknown * 100 / all).round(2)
    summary['count_ok'] = ok.count
    summary['count_fail'] = failed.count
    summary['count_unknown'] = unknown.count

    data['summary'] = summary

    data
  end
end
