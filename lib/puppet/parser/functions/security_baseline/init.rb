module Puppet::Parser::Functions

    newfunction(:'security_baseline::init') do |args|

      raise Puppet::ParseError, "security_baseline::init(): Wrong number of arguments (#{args.length}; must be = 1)" unless args.length = 1

      filename = args[0]
      File.delete(filename) if File.exist?(filename)
      File.open(filename, 'w') { |file|
        file.puts("ok:\n")
        file.puts("fail:\n")
        file.puts("unknown:\n")
      }

    end
end