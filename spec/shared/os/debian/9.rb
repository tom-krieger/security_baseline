shared_examples 'os::debian::9' do
  puts 'Debian 9 tests' if ENV['DEBUG'] == '1'
  include_examples 'common::freexvfs'
  include_examples 'common::jffs2'
  include_examples 'common::hfs'
  include_examples 'common::hfsplus'
  include_examples 'common::udf'
end
