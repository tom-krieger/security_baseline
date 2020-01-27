
Puppet::Functions.create_function(:'security_baseline::add') do
  local_types do
    type 'Stati = Enum[ok, fail, unknown, notchecked]'
  end

  dispatch :add do
    required_param 'String', :rule_nr
    required_param 'Stati', :status
    optional_param 'String', :filename
    optional_param 'Boolean', :debug
  end

  def add(rule_nr, status, filename = '/tmp/security_baseline_summary.txt', debug = false)
    call_function('info', "add called with #{rule_nr} and #{status}") if debug
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
    # call_function('info', "add #{data[status]}")
    File.open(filename, 'w') do |file|
      data.each do |key, val|
        file.puts("#{key}:#{val}\n")
      end
    end

    File.chmod(0o666, filename)

    nil
  end

  def get_file_content(file_to_read)
    tests_ok = ''
    tests_fail = ''
    tests_unknown = ''
    tests_notchecked = ''
    lines = File.open(file_to_read).readlines
    unless lines.nil? || lines.empty?
      lines.each do |line|
        if line =~ %r{^ok:}
          m = line.match(%r{^ok:(?<ok>.*)$})
          unless m.nil?
            tests_ok = m[:ok]
          end
        end
        if line =~ %r{^fail:}
          m = line.match(%r{^fail:(?<fail>.*)$})
          unless m.nil?
            tests_fail = m[:fail]
          end
        end
        if line =~ %r{^notchecked:}
          m = line.match(%r{^fail:(?<notchecked>.*)$})
          unless m.nil?
            tests_notchecked = m[:notchecked]
          end
        end
        next unless line =~ %r{^unknown:}
        m = line.match(%r{^unknown:(?<unknown>.*)$})
        unless m.nil?
          tests_unknown = m[:unknown]
        end
      end
    end

    data = {}
    data['ok'] = tests_ok
    data['fail'] = tests_fail
    data['unknown'] = tests_unknown
    data['notchecked'] = tests_notchecked

    data
  end
end
