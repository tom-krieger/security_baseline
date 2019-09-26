# get facts about installed packages

def get_facts_packages_installed
  packages_installed = {}
  packages = { 'iptables' => '-q',
               'openldap-clients' => '-q',
               'mcstrans' => '-q',
               'prelink' => '-q',
               'rsh' => '-q',
               'libselinux' => '-q',
               'setroubleshoot' => '-q',
               'talk' => '-q',
               'tcp_wrappers' => '-q',
               'telnet' => '-q',
               'ypbind' => '-q',
               'rsyslog' => '-q' }

  packages.each do |package, opts|
    packages_installed[package] = check_package_installed(package, opts)
  end

  packages_installed
end
