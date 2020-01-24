Puppet::Functions.create_function(:'security_baseline::summary') do
  dispatch :init do
  end

  dispatch :add do
    param 'String', :rule_nr
    param 'String', :status
  end

  dispatch :summary do
  end

  dispatch :cleanup do
  end

  def remove_old_file
    if File.exist?('/tmp/security_baseline_summary.txt')
      File.delete('/tmp/security_baseline_summary.txt')
    end
  end

  def get_file_content(file_to_read)
    tests_ok = ''
    tests_fail = ''
    tests_unknown = ''
    content = File.open(file_to_read).readlines
    unless lines.empty? || lines.nil?
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

  def init
    remove_old_file
  end

  def add(rule_nr, status)
    if File.exist?('/tmp/security_baseline_summary.txt')
      data = get_file_content('/tmp/security_baseline_summary.txt')

      if status == 'ok' || status == 'fail' || status == 'unknoen'
        data[status] = if data[status].empty?
                         rule_nr
                       else
                         "#{data[status]}#:##{rule_nr}"
                       end
      end
    end
  end

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

  def cleanup
    remove_old_file
  end
end
