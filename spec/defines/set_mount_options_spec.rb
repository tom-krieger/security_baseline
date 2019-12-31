require 'spec_helper'
require 'pp'

mpts = ['/dev/shm', '/home', '/tmp', '/var/tmp']
opts = ['nodev', 'noexec', 'nosuid']

mpts.each do |mpt|
  opts.each do |opt|
    describe 'security_baseline::set_mount_options' do
      on_supported_os.each do |os, os_facts|
        context "on #{os}, with #{mpt}, #{opt}" do
          let(:title) { "#{mpt}-#{opt}" }
          let(:params) do
            {
              'mountpoint'   => "#{mpt}",
              'mountoptions' => "#{opt}",
            }
          end
          let(:facts) { os_facts }

          it { 
            is_expected.to compile 
            aug = "/etc/fstab - work on #{mpt} with #{opt}"
            exc = "Exec[remount #{mpt} with #{opt}]"
            is_expected.to contain_augeas(aug)
              .with(
                'context' => '/files/etc/fstab',
                'changes' => [
                  "ins opt after /files/etc/fstab/*[file = '#{mpt}']/opt[last()]",
                  "set *[file = '#{mpt}']/opt[last()] #{opt}",
                ],
                'onlyif'  => "match *[file = '#{mpt}']/opt[. = '#{opt}'] size == 0",
              )
              .that_notifies(exc)

            is_expected.to contain_exec("remount #{mpt} with #{opt}")
              .with(
                'command'     => "mount -o remount #{mpt}",
                'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'refreshonly' => true,
              )
          }
        end
      end
    end
  end
end
