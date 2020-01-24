module Puppet::Parser::Functions

    newfunction(:'security_baseline::init') do |args|

      raise Puppet::ParseError, "security_baseline::init(): Wrong number of arguments (#{args.length}; must be = 0)" unless args.length = 0

      File.delete('/tmp/security_baseline_summary.txt') if File.exist?('/tmp/security_baseline_summary.txt')
      File.open('/tmp/security_baseline_summary.txt', 'w') { |file|
        file.puts("ok:\n")
        file.puts("fail:\n")
        file.puts("unknown:\n")
      }
      
    end
end