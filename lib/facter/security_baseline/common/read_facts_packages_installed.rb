# frozen_string_literal: true

# get facts about installed packages

def read_facts_packages_installed(packages)
  packages_installed = {}
  packages.each do |package, opts|
    packages_installed[package] = check_package_installed(package, opts)
  end

  packages_installed
end
