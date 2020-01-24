require 'puppet/functions/security_baseline/helper'

Puppet::Functions.create_function(:'security_baseline::cleanup') do

  dispatch :cleanup do
  end

  def cleanup
    remove_old_file
  end
end