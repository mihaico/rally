# Copyright 2014: Rackspace UK
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import pkgutil

from rally.common import logging
from rally.common import sshutils
from rally.common import winrmutils
from rally import consts
from rally import exceptions
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.vm import utils as vm_utils
from rally.plugins.openstack.services import heat
from rally.task import atomic
from rally.task import types
from rally.task import validation

import tempfile
import time
import random
import six

LOG = logging.getLogger(__name__)


class VMTasks(vm_utils.VMScenario):
    """Benchmark scenarios that are to be run inside VM instances."""

    def __init__(self, *args, **kwargs):
        super(VMTasks, self).__init__(*args, **kwargs)

    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @validation.image_valid_on_flavor("flavor", "image")
    @validation.valid_command("command")
    @validation.number("port", minval=1, maxval=65535, nullable=True,
                       integer_only=True)
    @validation.external_network_exists("floating_network")
    @validation.required_services(consts.Service.NOVA, consts.Service.CINDER)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova", "cinder"],
                                 "keypair": {}, "allow_ssh": {}})
    def boot_runcommand_delete(self, image, flavor,
                               username,
                               password=None,
                               command=None,
                               volume_args=None,
                               floating_network=None,
                               port=22,
                               use_floating_ip=True,
                               force_delete=False,
                               wait_for_ping=True,
                               max_log_length=None,
                               **kwargs):
        """Boot a server, run script specified in command and delete server.

        Example Script in samples/tasks/support/instance_dd_test.sh

        The script to be executed is provided like command['remote_path'] or
        command['local_path'] and interpreter in command['interpreter']
        respectively.

        :param image: glance image name to use for the vm
        :param flavor: VM flavor name
        :param username: ssh username on server, str
        :param password: Password on SSH authentication
        :param command: Command-specifying dictionary that either specifies
            remote command path via `remote_path' (can be uploaded from a
            local file specified by `local_path`), an inline script via
            `script_inline' or a local script file path using `script_file'.
            Both `script_file' and `local_path' are checked to be accessible
            by the `file_exists' validator code.

            The `script_inline' and `script_file' both require an `interpreter'
            value to specify the interpreter script should be run with.

            Note that any of `interpreter' and `remote_path' can be an array
            prefixed with environment variables and suffixed with args for
            the `interpreter' command. `remote_path's last component must be
            a path to a command to execute (also upload destination if a
            `local_path' is given). Uploading an interpreter is possible
            but requires that `remote_path' and `interpreter' path do match.


            Examples::

                # Run a `local_script.pl' file sending it to a remote
                # Perl interpreter
                command = {
                    "script_file": "local_script.pl",
                    "interpreter": "/usr/bin/perl"
                }

                # Run an inline script sending it to a remote interpreter
                command = {
                    "script_inline": "echo 'Hello, World!'",
                    "interpreter": "/bin/sh"
                }

                # Run a remote command
                command = {
                    "remote_path": "/bin/false"
                }

                # Copy a local command and run it
                command = {
                    "remote_path": "/usr/local/bin/fio",
                    "local_path": "/home/foobar/myfiodir/bin/fio"
                }

                # Copy a local command and run it with environment variable
                command = {
                    "remote_path": ["HOME=/root", "/usr/local/bin/fio"],
                    "local_path": "/home/foobar/myfiodir/bin/fio"
                }

                # Run an inline script sending it to a remote interpreter
                command = {
                    "script_inline": "echo \"Hello, ${NAME:-World}\"",
                    "interpreter": ["NAME=Earth", "/bin/sh"]
                }

                # Run an inline script sending it to an uploaded remote
                # interpreter
                command = {
                    "script_inline": "echo \"Hello, ${NAME:-World}\"",
                    "interpreter": ["NAME=Earth", "/tmp/sh"],
                    "remote_path": "/tmp/sh",
                    "local_path": "/home/user/work/cve/sh-1.0/bin/sh"
                }


        :param volume_args: volume args for booting server from volume
        :param floating_network: external network name, for floating ip
        :param port: ssh port for SSH connection
        :param use_floating_ip: bool, floating or fixed IP for SSH connection
        :param force_delete: whether to use force_delete for servers
        :param wait_for_ping: whether to check connectivity on server creation
        :param **kwargs: extra arguments for booting the server
        :param max_log_length: The number of tail nova console-log lines user
                               would like to retrieve
        :returns: dictionary with keys `data' and `errors':
                  data: dict, JSON output from the script
                  errors: str, raw data from the script's stderr stream
        """

        if volume_args:
            volume = self._create_volume(volume_args["size"], imageRef=None)
            kwargs["block_device_mapping"] = {"vdrally": "%s:::1" % volume.id}

        server, fip = self._boot_server_with_fip(
            image, flavor, use_floating_ip=use_floating_ip,
            floating_network=floating_network,
            key_name=self.context["user"]["keypair"]["name"],
            **kwargs)
        try:
            if wait_for_ping:
                self._wait_for_ping(fip["ip"])

            code, out, err = self._run_command(
                fip["ip"], port, username, password, command=command)
            if code:
                raise exceptions.ScriptError(
                    "Error running command %(command)s. "
                    "Error %(code)s: %(error)s" % {
                        "command": command, "code": code, "error": err})

            try:
                data = json.loads(out)
            except ValueError as e:
                raise exceptions.ScriptError(
                    "Command %(command)s has not output valid JSON: %(error)s."
                    " Output: %(output)s" % {
                        "command": command, "error": str(e), "output": out})
        except (exceptions.TimeoutException,
                exceptions.SSHTimeout):
            console_logs = self._get_server_console_output(server,
                                                           max_log_length)
            LOG.debug("VM console logs:\n%s", console_logs)
            raise

        finally:
            self._delete_server_with_fip(server, fip,
                                         force_delete=force_delete)

        if type(data) != dict:
            raise exceptions.ScriptError(
                "Command has returned data in unexpected format.\n"
                "Expected format: {"
                "\"additive\": [{chart data}, {chart data}, ...], "
                "\"complete\": [{chart data}, {chart data}, ...]}\n"
                "Actual data: %s" % data)

        if set(data) - {"additive", "complete"}:
            LOG.warning(
                "Deprecated since Rally release 0.4.1: command has "
                "returned data in format {\"key\": <value>, ...}\n"
                "Expected format: {"
                "\"additive\": [{chart data}, {chart data}, ...], "
                "\"complete\": [{chart data}, {chart data}, ...]}")
            output = None
            try:
                output = [[str(k), float(v)] for k, v in data.items()]
            except (TypeError, ValueError):
                raise exceptions.ScriptError(
                    "Command has returned data in unexpected format.\n"
                    "Expected format: {key1: <number>, "
                    "key2: <number>, ...}.\n"
                    "Actual data: %s" % data)
            if output:
                self.add_output(additive={"title": "Command output",
                                          "chart_plugin": "Lines",
                                          "data": output})
        else:
            for chart_type, charts in data.items():
                for chart in charts:
                    self.add_output(**{chart_type: chart})

    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @validation.number("port", minval=1, maxval=65535, nullable=True,
                       integer_only=True)
    @validation.valid_command("command")
    @validation.external_network_exists("floating_network")
    @validation.required_services(consts.Service.NOVA, consts.Service.CINDER)
    @validation.required_openstack(users=True)
    @validation.required_contexts("image_command_customizer")
    @scenario.configure(context={"cleanup": ["nova", "cinder"],
                                 "keypair": {}, "allow_ssh": {}})
    def boot_runcommand_delete_custom_image(self, **kwargs):
        """Boot a server from a custom image, run a command that outputs JSON.

        Example Script in rally-jobs/extra/install_benchmark.sh
        """

        return self.boot_runcommand_delete(
            image=self.context["tenant"]["custom_image"]["id"], **kwargs)

    @scenario.configure(context={"cleanup": ["nova", "heat"],
                                 "keypair": {}, "network": {}})
    def runcommand_heat(self, workload, template, files, parameters):
        """Run workload on stack deployed by heat.

        Workload can be either file or resource:

        .. code-block: json

            {"file": "/path/to/file.sh"}
            {"resource": ["package.module", "workload.py"]}

        Also it should contain "username" key.

        Given file will be uploaded to `gate_node` and started. This script
        should print `key` `value` pairs separated by colon. These pairs will
        be presented in results.

        Gate node should be accessible via ssh with keypair `key_name`, so
        heat template should accept parameter `key_name`.

        :param workload: workload to run
        :param template: path to heat template file
        :param files: additional template files
        :param parameters: parameters for heat template
        """
        keypair = self.context["user"]["keypair"]
        parameters["key_name"] = keypair["name"]
        network = self.context["tenant"]["networks"][0]
        parameters["router_id"] = network["router_id"]
        self.stack = heat.main.Stack(self, self.task,
                                     template, files=files,
                                     parameters=parameters)
        self.stack.create()
        for output in self.stack.stack.outputs:
            if output["output_key"] == "gate_node":
                ip = output["output_value"]
                break
        ssh = sshutils.SSH(workload["username"], ip, pkey=keypair["private"])
        ssh.wait()
        script = workload.get("resource")
        if script:
            script = pkgutil.get_data(*script)
        else:
            script = open(workload["file"]).read()
        ssh.execute("cat > /tmp/.rally-workload", stdin=script)
        ssh.execute("chmod +x /tmp/.rally-workload")
        with atomic.ActionTimer(self, "runcommand_heat.workload"):
            status, out, err = ssh.execute(
                "/tmp/.rally-workload",
                stdin=json.dumps(self.stack.stack.outputs))
        rows = []
        for line in out.splitlines():
            row = line.split(":")
            if len(row) != 2:
                raise exceptions.ScriptError("Invalid data '%s'" % line)
            rows.append(row)
        if not rows:
            raise exceptions.ScriptError("No data returned. Original error "
                                         "message is %s" % err)
        self.add_output(
            complete={"title": "Workload summary",
                      "description": "Data generated by workload",
                      "chart_plugin": "Table",
                      "data": {
                          "cols": ["key", "value"],
                          "rows": rows}}
        )

    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @validation.number("port", minval=1, maxval=65535, nullable=True,
                       integer_only=True)
    @validation.external_network_exists("floating_network")
    @validation.image_valid_on_flavor("flavor", "image")
    @validation.required_contexts("network")
    @validation.required_services(consts.Service.NOVA)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova"], "keypair": {},
                                 "allow_ssh": {}})
    def boot_and_delete_server_test_ssh(self, image, flavor,
                                        username,
                                        password=None,
                                        command=None,
                                        port=22,
                                        use_floating_ip=True,
                                        floating_network=None,
                                        force_delete=False,
                                        **kwargs):
        server, fip = self._boot_server_with_fip(
            image, flavor, use_floating_ip=use_floating_ip,
            floating_network=floating_network,
            key_name=self.context["user"]["keypair"]["name"],
            **kwargs)

        pkey = self.context["user"]["keypair"]["private"]
        ssh = sshutils.SSH(username, fip["ip"], port=port,
                           pkey=pkey, password=password)
        self._wait_for_ssh(ssh)

        self._delete_server_with_fip(server, fip, force_delete=force_delete)

    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @validation.number("port", minval=1, maxval=65535, nullable=True,
                       integer_only=True)
    @validation.external_network_exists("floating_network")
    @validation.image_valid_on_flavor("flavor", "image")
    @validation.required_contexts("network")
    @validation.required_services(consts.Service.NOVA)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova"], "keypair": {},
                                 "allow_ssh": {}})
    def create_launch_job_sequence(self, image, flavor,
                                   username,
                                   jobs,
                                   use_floating_ip=True,
                                   floating_network=None,
                                   force_delete=False,
                                   interval_sleep=1,
                                   **kwargs):
        glance = self.clients("glance")
        nova = self.clients("nova")
        os_distro = glance.images.get(image).properties.get('os_distro')
        if os_distro is None:
            raise Exception("Please set os distro for image %(image)s,"
                            " currently is set to %(os_distro)s" %
                            {'image': image, 'os_distro': os_distro})
        if os_distro != 'windows' and os_distro != 'ubuntu':
            raise Exception("Supported os_distro: windows and ubuntu")

        server, fip = self._boot_server_with_fip(
            image, flavor, use_floating_ip=use_floating_ip,
            floating_network=floating_network,
            key_name=self.context["user"]["keypair"]["name"],
            **kwargs)
        private_key = self.context["user"]["keypair"]["private"]
        password = None

        if os_distro == 'windows':
            self._wait_for_ping_windows(fip['ip'])
            with tempfile.NamedTemporaryFile() as ntf:
                ntf.write(private_key)
                ntf.flush()
                password = ''
                while (password == ''):
                    password = nova.servers.get_password(server.id,
                                                         ntf.name)
                    if password != '':
                        LOG.debug(password)
                    time.sleep(interval_sleep)
                ntf.close()
        else:
            self._wait_for_ping_linux(fip['ip'])

        self._wait_for_hadoop_to_start(fip['ip'],
                                       os_distro=os_distro,
                                       username=username,
                                       password=password,
                                       pkey=private_key)

        for idx, job in enumerate(jobs):
            LOG.debug("Launching Job. Sequence #%d" % idx)
            if os_distro == 'windows':
                CMD = ('hadoop jar C:\\hadoop-examples.jar'
                       ' %(job)s %(arg)s %(args)s')
            else:
                CMD = ('~/hadoop-2.7.1/bin/hadoop jar ~/hadoop-examples.jar'
                       ' %(job)s %(arg)s %(args)s')

            command = CMD % {'job': job['job_name'].lower(),
                             'arg': job['args'][0],
                             'args': job['args'][1]}

            if os_distro == 'windows':
                self._run_job_winrm(idx, fip['ip'], username,
                                    password, command)
            if os_distro == 'ubuntu':
                self._run_job_ssh(idx, fip['ip'], username,
                                  private_key, command)

        self._delete_server_with_fip(server, fip, force_delete=force_delete)

    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @validation.number("port", minval=1, maxval=65535, nullable=True,
                       integer_only=True)
    @validation.external_network_exists("floating_network")
    @validation.image_valid_on_flavor("flavor", "image")
    @validation.required_contexts("network")
    @validation.required_services(consts.Service.NOVA)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova"], "keypair": {},
                                 "allow_ssh": {}})
    def windows_performance_test(self, image, flavor,
                                 username,
                                 password=None,
                                 use_floating_ip=True,
                                 floating_network=None,
                                 force_delete=False,
                                 password_sleep_interval=1,
                                 file_size=10,
                                 random_string_size=2,
                                 retry_count_winrm=120,
                                 **kwargs):
        user_data = (
            '#ps1\n'
            'Get-NetConnectionProfile | Set-NetConnectionProfile '
            '-NetworkCategory Private\n'
            'netsh firewall set opmode mode=disable profile=all\n'
            'Start-Service winrm\n'
            'winrm quickconfig -q\n'
            'winrm set winrm/config/service \'@{AllowUnencrypted="true"}\'\n'
            'winrm set winrm/config/winrs \'@{MaxMemoryPerShellMB="%s"}\''
            % ((random_string_size + 1) * 1024))
        # We need to set the MaxMemoryPerShell in order to use a higher number
        # for the memory test

        server, fip = self._boot_server_with_fip(
            image, flavor, use_floating_ip=use_floating_ip,
            floating_network=floating_network,
            key_name=self.context["user"]["keypair"]["name"],
            userdata=user_data,
            **kwargs)

        self._wait_for_ping_windows(fip['ip'])

        private_key = self.context["user"]["keypair"]["private"]
        password = ''
        nova = self.clients("nova")
        with tempfile.NamedTemporaryFile() as ntf:
            ntf.write(private_key)
            ntf.flush()
            while not password:
                password = nova.servers.get_password(server.id,
                                                     ntf.name)
                if password:
                    LOG.debug("Password was found: %s" % password)
                else:
                    LOG.debug("Password was not found, retrying...")
                    time.sleep(password_sleep_interval)
            ntf.close()

        retry_count = retry_count_winrm
        winrm_client = winrmutils.WinrmClient(
            server_ip=fip['ip'],
            username=username,
            password=password)
        while True:
            try:
                # Test the winrm connection by running a simple command
                winrm_client.run_ps('ls')
                break
            except winrmutils.winrm.exceptions.InvalidCredentialsError:
                retry_count = retry_count - 1
                if retry_count == 0:
                    raise
                time.sleep(1)

        self.scripts_path = vm_utils.__file__
        self.scripts_path = self.scripts_path[0:self.scripts_path.rfind("/")]

        # NOTE(abalutoiu): Filesize is in GB
        def job_1(self, winrm_client, file_size):
            f = open(self.scripts_path + '/create_large_file.ps1')
            script = f.read()
            script = script % {'max_size': file_size}
            LOG.debug("Running script:\n%s" % script)
            with atomic.ActionTimer(
                    self,
                    "Create a large random file (size: %sGB)" % file_size):
                winrm_client.run_powershell(script)

        def job_2(self, winrm_client):
            f = open(self.scripts_path + '/create_zip_file.ps1')
            script = f.read()
            LOG.debug("Running script:\n%s" % script)
            with atomic.ActionTimer(
                    self,
                    "Create a zip file using the previous file"):
                winrm_client.run_powershell(script)

        # NOTE(abalutoiu): Random string size is in GB
        def job_3(self, winrm_client):
            f = open(self.scripts_path + '/generate_random_string.ps1')
            script = f.read()
            script = script % {'max_size': random_string_size}
            LOG.debug("Running script:\n%s" % script)
            with atomic.ActionTimer(
                    self,
                    ("Generate a %sGB random string in memory "
                     "(to stress memory IO)" % random_string_size)):
                winrm_client.run_powershell(script)

        @atomic.action_timer("Start a web browser, loading and running a "
                             "local page including a stress JS script")
        def job_4(self, winrm_client):
            pass

        job_1(self, winrm_client, file_size)
        job_2(self, winrm_client)
        job_3(self, winrm_client)
        # job_4(self, winrm_client)

        self._delete_server_with_fip(server, fip, force_delete=force_delete)

    @types.convert(image_ref={"type": "glance_image"},
                   image_ref_alt={"type": "glance_image"},
                   flavor_ref={"type": "nova_flavor"})
    @validation.number("port", minval=1, maxval=65535, nullable=True,
                       integer_only=True)
    @validation.external_network_exists("floating_network")
    @validation.image_valid_on_flavor("flavor_ref", "image_ref")
    @validation.required_contexts("network")
    @validation.required_services(consts.Service.NOVA)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova"], "keypair": {},
                                 "allow_ssh": {}})
    def ovs_iperf_test(self,
                       image_ref,
                       image_ref_alt,
                       flavor_ref,
                       win_user,
                       win_pass,
                       image_ssh_user,
                       image_ssh_user_alt,
                       use_floating_ip=True,
                       floating_network=None,
                       force_delete=False,
                       size_to_test=200,
                       time_to_test=30,
                       random_string_size=2,
                       retry_count_winrm=120,
                       **kwargs):
        """OVS iperf test
        :param image_ref: Valid primary image reference to be used in the
            test Hyper-V OVS network. This is a required option.
        :param image_ref_alt: Valid secondary image reference to be used in the
            test Hyper-V OVS network. This is a required option.
        :param flavor_ref: Valid flavor to be used for the test Hyper-V OVS
        :param win_user: User for windows image
        :param win_pass: Password for windows image
        :param size_to_test: Data size in MBytes to be transferred
            during the test
        :param time_to_test: Unlimited data transfer during the given time
        :param image_ssh_user: SSH user for linux image
        :param image_ssh_user_alt: Alternage ssh user for alternate linux image
        """
        user_data = (
            '#ps1\n'
            'Get-NetConnectionProfile | Set-NetConnectionProfile '
            '-NetworkCategory Private\n'
            'netsh firewall set opmode mode=disable profile=all\n'
            'Start-Service winrm\n'
            'winrm quickconfig -q\n'
            'winrm set winrm/config/service \'@{AllowUnencrypted="true"}\'\n'
            'winrm set winrm/config/winrs \'@{MaxMemoryPerShellMB="%s"}\''
            % ((random_string_size + 1) * 1024))
        # We need to set the MaxMemoryPerShell in order to use a higher number
        # for the memory test
        size_to_test = None

        def check_image(glance_client, image_id):
            image = glance_client.images.get(image_id)
            img_prop = 'hypervisor_type'
            LOG.info(image)
            supported_hyper_types = ['qemu', 'hyperv']
            hyper_type = image.properties.get(img_prop, None)
            if not hyper_type:
                raise Exception(
                    'Please set %(img_prop)s for image %(image_id)s'
                    % {'img_prop': img_prop, 'image_id': image_id})
            if hyper_type not in supported_hyper_types:
                raise Exception(
                    'Hypervsior type used (%(hypervisor)s) for image %(image)s'
                    ' is not supported, use qemu or hyperv' %
                    {'hypervisor': hyper_type, 'image': image_id})
            _get_image_property(image_id, 'os_distro')

        def _get_image_property(image_id, img_prop,
                                glance_client=self.clients("glance")):
            image = glance_client.images.get(image_id)
            property_image = image.properties.get(img_prop, None)

            if not property_image:
                raise Exception(
                    'Please set %(img_prop)s for image %(image_id)s'
                    % {'img_prop': img_prop, 'image_id': image_id})

            return property_image

        def _find_diff_host(nova_client, server, diff_host=True):
            """Find a compute node for live migration.

            :param server: Server object
            """
            server_admin = nova_client.servers.get(server.id)
            host = getattr(server_admin, "OS-EXT-SRV-ATTR:host")
            az_name = getattr(server_admin, "OS-EXT-AZ:availability_zone")
            LOG.info("Got host %s, searching for a different host %s"
                     % (host, diff_host))
            az = None
            for a in nova_client.availability_zones.list():
                if az_name == a.zoneName:
                    az = a
                    break
            try:
                if diff_host:
                    new_host = random.choice(
                        [key for key, value in six.iteritems(az.hosts)
                            if key != host and
                            value.get("nova-compute",
                                      {}).get("available", False)])
                else:
                    new_host = random.choice(
                        [key for key, value in six.iteritems(az.hosts)
                            if key == host and
                            value.get("nova-compute",
                                      {}).get("available", False)])
                return az_name + ":" + new_host
            except IndexError:
                raise exceptions.InvalidHostException(
                    "No valid host found to migrate")

        def boot_server_with_fip(
                image_ref, self=self, flavor_ref=flavor_ref,
                use_floating_ip=use_floating_ip,
                floating_network=floating_network,
                key_name=self.context["user"]["keypair"]["name"],
                userdata=user_data,
                **kwargs):
            server, fip = self._boot_server_with_fip(
                image_ref, flavor_ref, use_floating_ip=use_floating_ip,
                floating_network=floating_network,
                key_name=self.context["user"]["keypair"]["name"],
                userdata=user_data,
                **kwargs)
            return server, fip

        def get_cmd(ip, tcp, size_to_test=size_to_test,
                    time_to_test=time_to_test):
            """Size is preferred over time for test."""
            if not size_to_test:
                option = '-t %(time)s' % {'time': time_to_test}
            else:
                option = '-n %(size)sM' % {'size': size_to_test}

            if tcp:
                cmd = 'iperf3 -c %(ip)s -f g -P8 -O5 -i 10 %(option)s' % {
                    'ip': ip, 'option': option}
            else:
                cmd = 'iperf3 -c %(ip)s -u -f g -b 0 -i 10 %(option)s' % {
                    'ip': ip, 'option': option}

            return cmd

        pkey = self.context["user"]["keypair"]["private"]

        def prepare_client_linux(ssh_client):
            try:
                ssh_client.execute('which iperf3')
                return  # return if command has exit code 0 (iperf3 installed)
            except Exception:
                pass  # exit code 1 (iperf3 uninstalled)

            try:  # exit code 127 if apt-get not found and exception is raised
                ssh_client.execute('apt-get')
                apt_get = True  # no exception raised, using apt-get
            except Exception:
                apt_get = False  # exception raised, using yum

            if apt_get:
                ssh_client.execute(
                    'sudo add-apt-repository "ppa:patrickdk/general-lucid" -y')
                ssh_client.execute('sudo apt-get update')
                ssh_client.execute('sudo apt-get install iperf3')
            else:
                ssh_client.execute('sudo firewall-cmd --permanent '
                                   '--zone=public --add-port=5201/tcp')
                ssh_client.execute('sudo firewall-cmd --permanent '
                                   '--zone=public --add-port=5201/udp')
                ssh_client.execute('sudo firewall-cmd --reload')

                ssh_client.execute('sudo yum install screen -y')
                ssh_client.execute('sudo yum install epel-release -y')
                """
                yum check-update returns an exit code of 100 if there are
                updates available. It will raise an exception which
                should be skipped
                """
                try:
                    ssh_client.execute('sudo yum check-update')
                except Exception:
                    pass
                ssh_client.execute('sudo yum install iperf3 -y')

        def prepare_client_windows(winrm_client):
            try:
                winrm_client.run_powershell('Get-Command iperf3')
                return  # if iperf3 is installed, the command will succeed
            except:
                pass  # ieprf3 not found, install it

            _retry_count = 0
            _max_retry_number = 3
            try:
                url = 'http://files.budman.pw/iperf3_10.zip'
                loc = 'C:\iperf3.zip'
                cmd = 'powershell wget %(url)s -OutFile %(loc)s' % {
                    'url': url, 'loc': loc}

                while True:
                    try:
                        winrm_client.exec_cmd(cmd)
                        break
                    except Exception:
                        _retry_count += 1
                        if _retry_count == _max_retry_number:
                            raise Exception

                target_dir = 'C:\\'
                cmd = ("$shellApplication = new-object -com shell.application"
                       "\n$zipPackage = $shellApplication.NameSpace('%(loc)s')"
                       "\n$destinationFolder = $shellApplication."
                       "NameSpace('%(target_dir)s')"
                       "\n$destinationFolder.CopyHere($zipPackage.Items())\n"
                       % {'loc': loc, 'target_dir': target_dir})
                winrm_client.run_powershell(cmd)
            except Exception:
                raise Exception('Could not install iperf3 for windows')

        def prepare_client(os, ip, username, server):
            if os == 'windows':
                password = get_windows_password(server)
                winrm_client = winrmutils.WinrmClient(ip, username, password)
                prepare_client_windows(winrm_client)
            else:
                ssh_client = sshutils.SSH(image_ssh_user, ip, pkey=pkey)
                ssh_client.wait()
                prepare_client_linux(ssh_client)

        def wait_for_ping(os, ip):
            if os == 'windows':
                self._wait_for_ping_windows(ip)
            else:
                self._wait_for_ping_linux(ip)

        def get_windows_password(server):
            if win_pass is not None:
                return win_pass

            private_key = self.context["user"]["keypair"]["private"]
            password = ''
            nova = self.clients("nova")
            with tempfile.NamedTemporaryFile() as ntf:
                ntf.write(private_key)
                ntf.flush()
                while not password:
                    password = nova.servers.get_password(server.id,
                                                         ntf.name)
                    if password:
                        LOG.debug("Password was found: %s" % password)
                    else:
                        LOG.debug("Password was not found, retrying...")
                        time.sleep(1)
                ntf.close()
            return password

        def test_with_images(img_ref, img_ref_alt, image_ssh_user,
                             image_ssh_user_alt, diff_host,
                             glance_client=self.clients("glance")):
            server_1, fip_1 = boot_server_with_fip(image_ref)
            os_1 = _get_image_property(img_ref, 'os_distro')

            ips = server_1.networks.popitem()[1]
            prv_ip_1 = [x for x in ips if x != fip_1['ip']][0]
            # Skip the preparation, consider the image is alredy prepared
            # prepare_client(os_1, fip_1['ip'], image_ssh_user, server_1)
            LOG.info("Waiting for ping on VM with ip %s" % fip_1['ip'])
            wait_for_ping(os_1, fip_1['ip'])
            LOG.info("VM with ip %s is ready" % fip_1['ip'])
            LOG.info("Going to use the private ip for tests: %s" % prv_ip_1)

            new_host = _find_diff_host(self.admin_clients("nova"),
                                       server_1, diff_host=diff_host)
            LOG.info("New VM booting on host %s" % new_host)
            server_2, fip_2 = boot_server_with_fip(
                image_ref_alt,
                availability_zone=new_host)
            LOG.info("New VM booted on host %s" % new_host)
            os_2 = _get_image_property(img_ref_alt, 'os_distro')

            ips = server_2.networks.popitem()[1]
            prv_ip_2 = [x for x in ips if x != fip_2['ip']][0]
            # Skip the preparation, consider the image is alredy prepared
            # prepare_client(os_2, fip_2['ip'], image_ssh_user_alt, server_2)
            LOG.info("Waiting for ping on VM with ip %s" % fip_2['ip'])
            wait_for_ping(os_2, fip_2['ip'])
            LOG.info("VM with ip %s is ready" % fip_2['ip'])
            LOG.info("Going to use the private ip for tests: %s" % prv_ip_2)

            # First VM (img_1) is sender - second VM (img_2) is receiver
            send_iperf3_server(fip_2['ip'], os_2, image_ssh_user_alt)
            # _, ip4 = self._get_server_port_id_and_ip4(self.instance_2)
            # ip4 = fip_2['ip']
            # Test using the private ip
            ip4 = prv_ip_2
            LOG.info("Running first test iperf3 client")
            send_iperf3_client(fip_1['ip'], ip4, os_1, image_ssh_user)
            log_results(img_ref, img_ref_alt, os_1, os_2,
                        diff_host, reverse=True)
            # First VM (img_1) is receiver - second VM (img_2) is sender
            send_iperf3_server(fip_1['ip'], os_1, image_ssh_user)
            # _, ip4 = self._get_server_port_id_and_ip4(self.instance_1)
            # ip4 = fip_1['ip']
            # Test using the private ip
            ip4 = prv_ip_1
            LOG.info("Running second test iperf3 client")
            send_iperf3_client(fip_2['ip'], ip4, os_2, image_ssh_user_alt)
            log_results(img_ref, img_ref_alt, os_1, os_2,
                        diff_host, reverse=False)

            # Cleanup
            self._delete_server_with_fip(
                server_1, fip_1, force_delete=force_delete)
            self._delete_server_with_fip(
                server_2, fip_2, force_delete=force_delete)

        def send_winrm_iperf3_server(ip, win_user=win_user, win_pass=win_pass):
            LOG.info("Going to use %s:%s to connect through winrm"
                     % (win_user, win_pass))
            winrm_client = winrmutils.WinrmClient(ip, win_user, win_pass)
            winrm_client.run_powershell("Set-NetFirewallProfile -Profile "
                                        "Domain,Public,Private -Enabled False")
            LOG.info("Preparing to send winrm iperf server to host %s" % ip)
            winrm_client.exec_cmd(
                'C:\\Users\\Administrator\\Downloads\\iperf-3.1.2-win64\\'
                'iperf3 -s -D', check_output=False)
            LOG.info("iperf server started on host %s through winrm" % ip)

        def send_winrm_iperf3_client(host_ip, to_ip, win_user=win_user,
                                     win_pass=win_pass):
            winrm_client = winrmutils.WinrmClient(host_ip, win_user, win_pass)
            winrm_client.run_powershell("Set-NetFirewallProfile -Profile "
                                        "Domain,Public,Private -Enabled False")
            LOG.info("Starting tests on host %s" % host_ip)
            try:
                cmd_tcp = (
                    'C:\\Users\\Administrator\\Downloads\\iperf-3.1.2-win64\\'
                    '%(cmd)s' % {'cmd': get_cmd(to_ip, tcp=True)})
                LOG.info("Starting iperf3 tcp with: %s" % cmd_tcp)
                self.tcp_result = winrm_client.exec_cmd(cmd_tcp)
                LOG.info("iperf3 tcp finished")
                cmd_udp = (
                    'C:\\Users\\Administrator\\Downloads\\iperf-3.1.2-win64\\'
                    '%(cmd)s' % {'cmd': get_cmd(to_ip, tcp=False)})
                LOG.info("Starting iperf3 udp with: %s" % cmd_udp)
                self.udp_result = winrm_client.exec_cmd(cmd_udp)
                LOG.info("iperf3 udp finished")

                self.tcp_result = self.tcp_result.std_out
                self.udp_result = self.udp_result.std_out
            except Exception:
                raise

        def send_ssh_iperf3_server(client):
            client.execute('screen -d -m iperf3 -s')

        def send_ssh_iperf3_client(client, to_ip):
            # execute :returns: tuple (exit_status, stdout, stderr)
            (_, self.tcp_result, _) = client.execute(get_cmd(to_ip, tcp=True))
            (_, self.udp_result, _) = client.execute(get_cmd(to_ip, tcp=False))

        def send_iperf3_server(ip, os, ssh_user):
            if os == 'windows':
                send_winrm_iperf3_server(ip=ip)
            else:
                ssh_client = sshutils.SSH(ssh_user, ip, pkey=pkey)
                ssh_client.wait()
                send_ssh_iperf3_server(ssh_client)

        def send_iperf3_client(host_ip, to_ip, os_host, ssh_user):
            if os_host == 'windows':
                send_winrm_iperf3_client(host_ip, to_ip)
            else:
                ssh_client = sshutils.SSH(ssh_user, host_ip, pkey=pkey)
                ssh_client.wait()
                send_ssh_iperf3_client(ssh_client, to_ip)

        def log_results(img_1, img_2, os_1, os_2, diff_host, reverse):
            type_1 = _get_image_property(img_1, 'hypervisor_type')
            type_2 = _get_image_property(img_2, 'hypervisor_type')

            if not diff_host:
                text = 'on the same host'
            else:
                text = 'on different hosts'
            LOG.info('Results for VMs %s' % text)
            LOG.info('First VM (%s) - Second VM (%s)' % (os_1, os_2))

            result = 'Results for %s - %s ' % (type_1, type_2)
            if not reverse:
                result = result + '(receiver - sender)'
            else:
                result = result + '(sender - receiver)'
            LOG.info(result)
            LOG.info('TCP test results: %s' % self.tcp_result)
            LOG.info('UDP test results: %s' % self.udp_result)

        @atomic.action_timer("ovs_iperf.test_diff_host")
        def test_diff_host(self):
            test_with_images(image_ref, image_ref_alt, image_ssh_user,
                             image_ssh_user_alt, diff_host=True)

        @atomic.action_timer("ovs_iperf.test_same_host")
        def test_same_host(self):
            test_with_images(image_ref, image_ref_alt, image_ssh_user,
                             image_ssh_user_alt, diff_host=False)

        @atomic.action_timer("ovs_iperf.test_same_host_first_image")
        def test_same_host_first_image(self):
            test_with_images(image_ref, image_ref, image_ssh_user,
                             image_ssh_user, diff_host=False)

        @atomic.action_timer("ovs_iperf.test_same_host_second_image")
        def test_same_host_second_image(self):
            test_with_images(image_ref_alt, image_ref_alt, image_ssh_user_alt,
                             image_ssh_user_alt, diff_host=False)

        # Check images
        check_image(self.clients("glance"), image_ref)
        check_image(self.clients("glance"), image_ref_alt)

        # # nova_client = self.admin_clients("nova")
        # server, fip = boot_server_with_fip(image_ref=image_ref)
        # server_2, fip_2 = boot_server_with_fip(image_ref=image_ref_alt)
        # LOG.info("%s %s" % (fip['ip'], fip_2['ip']))

        LOG.info("Running tests")
        test_diff_host(self)
        test_same_host(self)
        test_same_host_first_image(self)
        test_same_host_second_image(self)

        # # Cleanup
        # self._delete_server_with_fip(
        #     server, fip, force_delete=force_delete)
        # self._delete_server_with_fip(
        #     server_2, fip_2, force_delete=force_delete)
