Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
    optional_param 'String', :filename
  end

  def init(filename = '/tmp/security_baseline_summary.txt')
    if File.exist?(filename)
      call_function('info', "init cleanup #{filename}")
      File.delete(filename)
    end
  end
end