require 'spec_helper_acceptance'
require 'pp'

ppc = <<-PUPPETCODE
include security_baseline
PUPPETCODE

puts 'applying manifests'
fixture_path = File.expand_path(File.join(__FILE__, '../..', 'fixtures'))
ret = apply_manifest(ppc)
puts "retcode 1 = #{ret['exit_code']}"
puts "#{ret['stdout']}\n"

ret = apply_manifest(ppc, catch_changes: false)
puts "retcode 2 = #{ret['exit_code']}"
puts "#{ret['stdout']}\n"

ret = apply_manifest(ppc, catch_changes: true)
puts "retcode 3 = #{ret['exit_code']}"
puts "#{ret['stdout']}\n"

puts "#{os[:family]} #{os[:release]}"
osfamily = os[:family].downcase
release = os[:release].to_s[0]

case osfamily
when 'ubuntu'
  if os[:release].to_s == '18.04'
    describe 'Security baseline Ubuntu 18.04' do
      include_examples 'os::ubuntu::18.04'
    end
  end

when 'centos'
  case release
  when 6
    describe 'Security baseline CentOS 6' do
      include_examples 'os::centos::6'
    end
  when 7
    describe 'Security baseline CentOS 7' do
      include_examples 'os::centos::7'
    end
  when 8
    describe 'Security baseline CentOS 8' do
      include_examples 'os::centos::8'
    end
  end

when 'debian'
  case release
  when 9
    describe 'Security baseline Debian 9' do
    end
  end

when 'redhat'
  case release
  when 6
    describe 'Security baseline RedHat 6' do
    end
  when 7
    describe 'Security baseline RedHat 7' do
    end
  when 8
    describe 'Security baseline RedHat 8' do
    end
  end

when 'suse'
  describe 'Security baseline Suse SLES 12' do
  end
end
