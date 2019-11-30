# get facts about aide

def read_facts_aide(distid, os)
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

  case distid
  when %r{RedHatEnterprise|CentOS|Fedora}
    val = Facter::Core::Execution.exec("rpm -q --queryformat '%{version}' aide")
    if val.empty? || val =~ %r{not installed}
      aide['version'] = ''
      aide['status'] = 'not installed'
    else
      aide['version'] = val
      aide['status'] = 'installed'
    end
  when 'Debian'
    val = Facter::Core::Execution.exec('dpkg -s aide')
    if val.empty? || val =~ %r{not installed}
      aide['version'] = ''
      aide['status'] = 'not installed'
    else
      aide['version'] = val
      aide['status'] = 'installed'
    end
  when 'Ubuntu'
    val = Facter::Core::Execution.exec('dpkg -s aide')
    if val.empty? || val =~ %r{not installed}
      aide['version'] = ''
      aide['status'] = 'not installed'
    else
      aide['version'] = val
      aide['status'] = 'installed'
    end
  else
    if os.casecmp('suse').zero?
      val = Facter::Core::Execution.exec('rpm -q aide')
      if val.empty? || val =~ %r{not installed}
        aide['version'] = ''
        aide['status'] = 'not installed'
      else
        aide['version'] = val
        aide['status'] = 'installed'
      end
    end
  end

  aide
end
