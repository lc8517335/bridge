#
# Cookbook Name:: net
# Provider:: net
#
# Copyright 2014, Sam Su
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut

def set resource
  cmd = "ifconfig eth0 |grep 'inet addr' | cut -f 2 -d ':' | cut -f 1 -d ' '"
  rc = shell_out(cmd)
  if rc.valid_exit_codes.include?(0)
    net = node['bridge']['config']["#{resource.device}"]
    if net['status'].eql?('') or net['status'].nil?
      ip = %x{ifconfig eth0 |grep 'inet addr' | cut -f 2 -d ":" | cut -f 1 -d " "}.split[0].split('.')
      ip[0] = net['network'].split('.')[0]
      ip[1] = net['network'].split('.')[1]
      if node['bridge']['ip']['format_by_location']
        ip[2] = (ip[3].to_i-1) / 15 + 1
        ip[3] = (ip[3].to_i-1) % 15 + 1
      else
        ip[2] = ip[2]
        ip[3] = ip[3]
      end
      node.set['bridge']['config']["#{resource.device}"]['ip'] = ip.join('.')
      node.set['bridge']['config']["#{resource.device}"]['status'] = "initial"
    else
      Chef::Log.error("Cannot get the device info of #{resource.device}.")
    end
  end
end

action :create do
  set new_resource
  net = node['bridge']['config']["#{new_resource.device}"]
  bind_interface = node['openstack']['endpoints']['network-openvswitch']['bind_interface']
  bind_interface_conf = "/etc/sysconfig/network-scripts/ifcfg-#{bind_interface}"
  if !net['status'].nil? and net['status'].include?("initial")
    %x{echo "service network restart" >> /etc/rc.d/rc.local}
    %x{ifconfig #{new_resource.device} #{net['ip']}/16}
    %x{ifconfig #{bind_interface} 0}
    %x{sed -i '/^HWADDR/d' #{bind_interface_conf}}
    %x{sed -i '/^IPADDR/d' #{bind_interface_conf}}
    %x{sed -i '/^NETMASK/d' #{bind_interface_conf}}
    %x{sed -i 's/TYPE=Ethernet/TYPE=OVSPort/g' #{bind_interface_conf}}
    %x{sed -i 's/BOOTPROTO=static/BOOTPROTO=none/g' #{bind_interface_conf}}
    %x{echo 'DEVICETYPE=ovs' >> #{bind_interface_conf}}
    %x{echo 'OVS_BRIDGE=br-#{bind_interface}' >> #{bind_interface_conf}}
    %x{echo 'HOTPLUG=no' >> #{bind_interface_conf}}
    if not ::File.exist?(net['conf'])
      service "network" do
        action :enable
        subscribes :restart, "template[net['conf']]"
      end

      template net['conf'] do
        source "ifcfg-br.erb"
        mode 00644
        owner "root"
        group "root"
        variables({
                      :br => new_resource.device,
                      :ip => net['ip'],
                      :netmask => net['netmask']
                  })
        notifies :restart, "service[network]", :immediately
      end
      node.set['nic']['config']["#{new_resource.device}"]['status'] = "config"
    end
    new_resource.updated_by_last_action(true)
  end
end