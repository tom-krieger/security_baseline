shared_examples 'os::centos::6' do
  puts 'CentOS 6 tests' if ENV['DEBUG'] == '1'
  include_examples 'common::cramfs'
  include_examples 'common::freexvfs'
  include_examples 'common::jffs2'
  include_examples 'common::hfs'
  include_examples 'common::hfsplus'
  include_examples 'common::squashfs'
  include_examples 'common::udf'
  include_examples 'common::vfat'
end
