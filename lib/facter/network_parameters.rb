# frozen_string_literal: true

# network_parameters.rb
# Collect facts about krnel network parameters of interest

Facter.add('network_parameters') do
  confine :kernel => 'Linux'
  setcode do
    # There is lots of trailing whotespace in these files, are you writing them
    # in Vim? I would recommend VSCode or a plugin to strip exces whitespace
    # automatically
    ret = {}
    keys = ['net.ipv4.ip_forward', 'net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects',
      'net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route', 'net.ipv4.conf.all.accept_redirects',
      'net.ipv4.conf.default.accept_redirects', 'net.ipv4.conf.all.secure_redirects', 'net.ipv4.conf.all.log_martians',
      'net.ipv4.conf.default.log_martians', 'net.ipv4.icmp_echo_ignore_broadcasts', 'et.ipv4.icmp_ignore_bogus_error_responses',
      'net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.default.rp_filter', 'net.ipv4.tcp_syncookies',
      'net.ipv6.conf.all.accept_ra', 'net.ipv6.conf.default.accept_ra', 'net.ipv6.conf.all.accept_redirects',
      'net.ipv6.conf.default.accept_redirects', 'net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6']

    keys.each do |key|

      value = Facter::Core::Execution.exec("sysctl #{key}")
      if ! value.nil? and ! value.empty? 
        vals = value.split(%r{ = })
        ret[vals[0]] = vals[1]
      end

    end
    
    ret
  end
end
        