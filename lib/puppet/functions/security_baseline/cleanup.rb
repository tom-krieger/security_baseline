Puppet::Functions.create_function(:'security_baseline::cleanup') do
  dispatch :cleanup do
  end

  require 'helper'

  def cleanup
    remove_old_file
  end
end
