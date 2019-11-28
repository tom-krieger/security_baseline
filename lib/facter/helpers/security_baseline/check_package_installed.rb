# check if a package isinstalled
# params:
#    opts: rpm options to use
#    pkg:  package name to query

def check_package_installed(pkg, opts = '-q')
  os = Facter.value(:osfamily)
  if (os == 'RedHat') || (os == 'Suse')
    val = Facter::Core::Execution.exec("rpm #{opts} #{pkg}")
  elsif os == 'Debian'
    val = Facter::Core::Execution.exec("dpkg -s #{pkg}")
  end
  if val.empty? || val =~ %r{not installed}
    false
  else
    true
  end
end
