def check_ntp(conf, job)
  data = {}
  if File.exist?(conf)
    val = Facter::Core::Execution.exec("grep -h -E \"^restrict\" #{conf}")
    data['ntp_restrict'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec("grep -h -E \"^(server|pool)\" #{conf}")
    data['ntp_server'] = check_value_string(val, 'none')
  else
    data['ntp_restrict'] = 'none'
    data['ntp_server'] = 'none'
  end
  if File.exist?(job)
    val = Facter::Core::Execution.exec("grep -h -E \"^NTPD_OPTIONS\" #{job}")
    data['ntp_options'] = check_value_string(val, 'none')
  else
    data['ntp_options'] = 'none'
  end

  data['ntp_status'] = data['ntp_restrict'] != 'none' && data['ntp_server'] != 'none'

  data
end
