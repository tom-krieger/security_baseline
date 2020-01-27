Puppet::Functions.create_function(:'security_baseline::summary') do
  dispatch :sum do
    optional_param 'String', :filename
    optional_param 'Boolean', :cleanup
    optional_param 'Boolean', :debug
    return_type 'Hash'
  end

  require 'pp'

  def sum(filename = '/tmp/security_baseline_summary.txt', cleanup = false, debug = false)
    summary = {}
    data = {}

    if File.exist?(filename)
      call_function('info', "summary #{filename} found") if debug
      call_function('info', "summary #{cleanup}") if debug

      data = get_file_content(filename)
      ok = data['ok'].split('#:#')
      failed = data['fail'].split('#:#')
      unknown = data['unknown'].split('#:#')
      notchecked = data['notchecked'].split('#:#')
      all = ok.count + failed.count + unknown.count + notchecked.count
      # call_function('info', "summary #{ok} #{failed} #{unknown} #{all}")
      summary['percent_ok'] = (ok.count.to_f * 100 / all.to_f).round(2)
      summary['percent_fail'] = (failed.count.to_f * 100 / all.to_f).round(2)
      summary['percent_unknown'] = (unknown.count.to_f * 100 / all.to_f).round(2)
      summary['percent_notchecked'] (notchecked.count.to_f * 100 / all.to_f).round(2)
      summary['count_ok'] = ok.count
      summary['count_fail'] = failed.count
      summary['count_unknown'] = unknown.count
      summary['count_notchecked'] = notchecked.count

      data['summary'] = summary
      data['ok'].gsub!('#:#', ',')
      data['fail'].gsub!('#:#', ',')
      data['unknown'].gsub!('#:#', ',')
      data['notchecked'].gsub!('#:#', ',')

      # call_function('info', "summary #{filename} - data #{data}")

      if cleanup && File.exist?(filename)
        call_function('info', "summary cleanup #{filename}") if debug
        File.delete(filename)
      end
    else
      call_function('info', "summary #{filename} NOT found") if debug
    end

    data
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
