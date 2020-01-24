Puppet::Functions.create_function(:'security_baseline::cleanup') do
  dispatch :cleanup do
    optional_param 'String', :filename
  end

  def cleanup(filename = '/tmp/security_baseline_summary.txt')
    call_function('info', "cleanup #{filename}")
    if File.exist?(filename)
      File.delete(filename)
    else
      call_function('info', "cleanup #{filename} NOT found")
    end

    nil
  end
end
