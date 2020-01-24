
module Puppet::Parser::Functions
  newfunction(:'security_baseline::add', type: :rvalue, doc: <<-DOC) do |args|
      @summary
          Initialize summary file

      DOC

    stati = ['ok', 'fail', 'unknown']

    raise Puppet::ParseError, "security_baseline::add(): Wrong number of arguments (#{args.length}; must be = 2)" unless args.length == 2

    unless stati.include?(args[1])
      raise Puppet::ParseError, "security_baseline::add(): the second argument must be one of 'ok' or 'fail' or 'unknown'"
    end

    data = if File.exist?('/tmp/security_baseline_summary.txt')
             get_file_content('/tmp/security_baseline_summary.txt')
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

    File.open('/tmp/security_baseline_summary.txt', 'w') do |file|
      data.each do |key, val|
        file.puts("#{key}:#{val}\n")
      end
    end
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
