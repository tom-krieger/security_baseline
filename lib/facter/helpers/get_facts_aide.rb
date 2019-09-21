# get facts about aide

def get_facts_aide(distid)
  aide = {}
  cronentry = Facter::Core::Execution.exec('crontab -u root -l | grep aide')
  fileentry = Facter::Core::Execution.exec('grep -rh aide /etc/cron.* /etc/crontab')

  if cronentry.empty? && fileentry.empty?
    aide['cron'] = 'undef'
  else
    unless cronentry.empty?
      aide['cron'] = cronentry
    end
    unless fileentry.empty?
      aide['cron'] = fileentry
    end
  end

  if distid =~ %r{RedHatEnterprise|CentOS|Fedora}
    val = Facter::Core::Execution.exec("rpm -q --queryformat '%{version}' aide")
    if val.empty? || val =~ %r{not installed}
      aide['version'] = ''
      aide['status'] = 'not installed'
    else
      aide['version'] = val
      aide['status'] = 'installed'
    end
  end

  aide
end