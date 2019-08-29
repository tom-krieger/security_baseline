# frozen_string_literal: true

# daytime_service.rb
# Check if daytime services are switched on

Facter.add('srv_daytime') do
    confine :osfamily => 'RedHat'
    setcode do
      ret = false
      srv = Facter::Core::Execution.exec("chkconfig --list 2>/dev/null | grep daytime")
      if srv.empty? then
        ret = false
      else
        srvs = srv.split("\n").strip()
        srvs.each do |line|
          data = line.split(%r{:}).strip()
          if data[1].strip().downcase() != 'off' then
            ret = true
          end
        end
      end
  
      ret
    end
  end
  