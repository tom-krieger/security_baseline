require 'spec_helper_acceptance'
require 'pp'

ppc = <<-PUPPETCODE
include security_baseline
PUPPETCODE

puts 'applying manifests' if ENV['DEBUG'] == '1'
# hiera_config_path = File.expand_path(File.join(__FILE__, '../../..', 'data/acceptance/hiera.yaml'))
hiera_config_path = '/etc/puppetlabs/code/environments/production/modules/security_baseline/data/acceptance/hiera.yaml'
# puts "hiera config #{hiera_config_path}"
ret = apply_manifest(ppc, hiera_config: hiera_config_path)
puts "retcode 1 = #{ret['exit_code']}" if ENV['DEBUG'] == '1'
# puts "#{ret['stderr']}\n"

ret = apply_manifest(ppc, hiera_config: hiera_config_path, catch_changes: false)
puts "retcode 2 = #{ret['exit_code']}" if ENV['DEBUG'] == '1'
# puts "#{ret['stderr']}\n"

ret = apply_manifest(ppc, hiera_config: hiera_config_path, catch_changes: false)
puts "retcode 3 = #{ret['exit_code']}" if ENV['DEBUG'] == '1'
# puts "#{ret['stderr']}\n"

osfamily = os[:family].downcase
release = os[:release].to_s.split('.')[0]

puts "#{os[:family]} #{os[:release]} #{release}" if ENV['DEBUG'] == '1'

case osfamily
when 'ubuntu'
  if os[:release].to_s == '18.04'
    describe 'Security baseline Ubuntu 18.04' do
      include_examples 'os::ubuntu::18.04'
    end
  else
    puts "unknown os: #{osfamily}-#{release}"
  end

when 'centos'
  case release
  when '6'
    describe 'Security baseline CentOS 6' do
      include_examples 'os::centos::6'
    end
  when '7'
    describe 'Security baseline CentOS 7' do
      include_examples 'os::centos::7'
    end
  when '8'
    describe 'Security baseline CentOS 8' do
      include_examples 'os::centos::8'
    end
  else
    puts "unknown os: #{osfamily}-#{release}"
  end

when 'debian'
  case release
  when '9'
    describe 'Security baseline Debian 9' do
      include_examples 'os::debian::9'
    end
  else
    puts "unknown os: #{osfamily}-#{release}"
  end

when 'redhat'
  case release
  when '6'
    describe 'Security baseline RedHat 6' do
      include_examples 'os::redhat::6'
    end
  when '7'
    describe 'Security baseline RedHat 7' do
      include_examples 'os::redhat::7'
    end
  when '8'
    describe 'Security baseline RedHat 8' do
      include_examples 'os::redhat::8'
    end
  else
    puts "unknown os: #{osfamily}-#{release}"
  end

when 'suse'
  case release
  when '12'
    describe 'Security baseline Suse SLES 12' do
    end
  else
    puts "unknown os: #{osfamily}-#{release}"
  end
else
  puts "unknown os: #{osfamily}"
end
