# check if a package isinstalled
# params:
#    opts: rpm options to use
#    pkg:  package name to query

def check_package_installed(pkg, opts = '-q')
  val = Facter::Core::Execution.exec("rpm #{opts} #{pkg}")
  if val.empty? || val =~ %r{not installed}
    false
  else
    true
  end
end
