require 'spec_helper_acceptance'
require 'pp'

ppc = <<-PUPPETCODE
include security_baseline
PUPPETCODE

puts 'applying manifests'
ret = apply_manifest(ppc)['exit_code']
puts "retcode = #{ret}"
if ret != 0
  ret = apply_manifest(ppc)['exit_code']
  puts "retcode = #{ret}"
end
apply_manifest(ppc, catch_changes: true)

puts "#{os[:family]} #{os[:release].to_s}"

release = os[:release].to_s[0]

case os[:family].downcase
when 'ubuntu'
  if os[:release].to_s == '18.04'
    describe 'Security baseline Ubuntu 18.04' do
      include_examples 'os::ubuntu::18.04'
    end
  end

when 'centos'
  case release
  when 6
  when 7
  when 8
  end

when 'debian'
  case release
  when 8
  when 8
  end

when 'redhat'
  case release
  when 6
  when 7
  when 8
  end

when 'suse'

end
