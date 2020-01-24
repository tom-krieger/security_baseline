Puppet::Functions.create_function(:'security_baseline::add') do
  dispatch :add do
    param 'String', :rule_nr
    param 'String', :status
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

