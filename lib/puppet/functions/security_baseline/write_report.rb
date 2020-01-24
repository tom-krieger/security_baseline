uppet::Functions.create_function(:'security_baseline::write_report') do
  dispatch :write_report do
    required_param 'String', :filename
  end

  require 'pp'

  def write_report(_filename)
    summary = {}
    data = {}

    return data unless File.exist?('/tmp/security_baseline_summary.txt')

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
    data['ok'].gsub!('#:#', ',')
    data['fail'].gsub!('#:#', ',')
    data['unknown'].gsub!('#:#', ',')
  end

  def get_file_content(file_to_read)
    tests_ok = ''
    tests_fail = ''
    tests_unknown = ''
    content = File.open(file_to_read).readlines
    unless lines.nil? || lines.empty?
      lines = content.split("\n")
      lines.each do |line|
        if line =~ %r{^ok:}
          m = line.match(%r{^ok: (?<ok>.*)$})
          unless m.nil?
            tests_ok = m[:ok]
          end
        end
        if line =~ %r{^fail:}
          m = line.match(%r{^nok: (?<fail>.*)$})
          unless m.nil?
            tests_fail = m[:fail]
          end
        end
        next unless line =~ %r{^unknown:}
        m = line.match(%r{^unknown: (?<unknown>.*)$})
        unless m.nil?
          tests_unknown = m[:unknown]
        end
      end
    end

    data = {}
    data['ok'] = tests_ok
    data['fail'] = tests_fail
    data['unknown'] = tests_unknown

    data
  end
end
