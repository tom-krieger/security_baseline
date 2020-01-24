
Puppet::Functions.create_function(:'security_baseline::init') do
  local_types do
    type 'Stati = Enum[pk, fail, unknown]'
  end

  dispatch :add do
    required_param 'String', :rule_nr
    required_param 'Stati', :status
    optional_parm 'String', :filename
  end

  def add(rule_nr, status, filename = '/tmp/security_baseline_summary.txt')

    data = if File.exist?(filename)
             get_file_content(filename)
           else
             {}
           end

    data[status] = if data[status].nil? || data[status].empty?
                     rule_nr
                   else
                     "#{data[status]}#:##{rule_nr}"
                   end

    pp 'data'
    pp data

    File.open(filename, 'w') do |file|
      data.each do |key, val|
        file.puts("#{key}:#{val}\n")
      end
    end

    nil
  end

  def get_file_content(file_to_read)
    tests_ok = ''
    tests_fail = ''
    tests_unknown = ''
    lines = File.open(file_to_read).readlines
    unless lines.nil? || lines.empty?
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
