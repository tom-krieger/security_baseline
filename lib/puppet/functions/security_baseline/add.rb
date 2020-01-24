Puppet::Functions.create_function(:'security_baseline::add') do
  dispatch :add do
    param 'String', :rule_nr
    param 'String', :status
  end

  require 'helper'

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
