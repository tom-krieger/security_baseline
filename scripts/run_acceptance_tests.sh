#!/bin/bash

# install all needed gems locally
pdk bundle install --quiet

# fire up two docker containers
# bundle exec rake 'litmus:provision[docker, centos:7]'
# bundle exec rake 'litmus:provision[docker, ubuntu:18.04]'
# pdk bundle exec rake 'litmus:provision[vagrant, centos/7]'
pdk bundle exec rake 'litmus:provision_list[dev_vagrant_all]'

# install Puppet agent
pdk bundle exec rake litmus:install_agent

# create symlink for puppet in vagrant environments
# workarround for secure_path settings in sudoers file
# pdk bundle exec bolt command run '[ -f /usr/local/bin/puppet ] || ln -s /opt/puppetlabs/puppet/bin/puppet /usr/local/bin/puppet' -i inventory.yaml --targets ssh_nodes
# pdk bundle exec bolt command run '[ -f /usr/bin/puppet ] || ln -s /opt/puppetlabs/puppet/bin/puppet /usr/bin/puppet' -i inventory.yaml --targets ssh_nodes

# install Puppet module to test
pdk bundle exec rake litmus:install_module

#pdk bundle exec bolt command run 'rm -f /etc/puppetlabs/code/environments/production/modules/security_baseline/data/*' -i inventory.yaml --targets ssh_nodes

#for f in `ls spec/fixtures/hiera/data/`; do
#   fn=`basename ${f}`
#   echo "uploading spec/fixtures/hiera/data/${f} to /etc/puppetlabs/code/environments/production/modules/security_baseline/data/${fn}"
#   bolt file upload spec/fixtures/hiera/data/${f} /etc/puppetlabs/code/environments/production/modules/security_baseline/data/${fn} -i inventory.yaml --targets ssh_nodes
#done

#pdk bundle exec bolt file upload spec/fixtures/hiera/hiera.yaml /etc/puppetlabs/code/environments/production/modules/security_baseline/hiera.yaml -i inventory.yaml --targets ssh_nodes

# run tests in parallel with less output
pdk bundle exec rake litmus:acceptance:parallel

# run tests with more output
# TARGET_HOST=localhost:2222 pdk bundle exec rspec ./spec/acceptance --format d
# TARGET_HOST=localhost:2223 pdk bundle exec rspec ./spec/acceptance --format d

# TARGET_HOST=127.0.0.1:2222 pdk bundle exec rspec ./spec/acceptance --format d

# tear down the test environment
pdk bundle exec rake litmus:tear_down

exit 0
