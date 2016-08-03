# Copyright 2013: Mirantis Inc.
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

import subprocess
import sys

import netaddr
from oslo_config import cfg
import six
import winrm
import time

from rally.common.i18n import _
from rally.common import logging
from rally.common import sshutils
from rally.plugins.openstack.scenarios.cinder import utils as cinder_utils
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.wrappers import network as network_wrapper
from rally.task import atomic
from rally.task import utils
from rally.task import validation

LOG = logging.getLogger(__name__)

VM_BENCHMARK_OPTS = [
    cfg.FloatOpt("vm_ping_poll_interval", default=1.0,
                 help="Interval between checks when waiting for a VM to "
                 "become pingable"),
    cfg.FloatOpt("vm_ping_timeout", default=120.0,
                 help="Time to wait for a VM to become pingable")]

CONF = cfg.CONF
benchmark_group = cfg.OptGroup(name="benchmark", title="benchmark options")
CONF.register_opts(VM_BENCHMARK_OPTS, group=benchmark_group)


class Host(object):

    ICMP_UP_STATUS = "ICMP UP"
    ICMP_DOWN_STATUS = "ICMP DOWN"

    name = "ip"

    def __init__(self, ip):
        self.ip = netaddr.IPAddress(ip)
        self.status = self.ICMP_DOWN_STATUS

    @property
    def id(self):
        return self.ip.format()

    @classmethod
    def update_status(cls, server):
        """Check ip address is pingable and update status."""
        ping = "ping" if server.ip.version == 4 else "ping6"
        if sys.platform.startswith("linux"):
            cmd = [ping, "-c1", "-w1", server.ip.format()]
        else:
            cmd = [ping, "-c1", server.ip.format()]

        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        proc.wait()
        LOG.debug("Host %s is ICMP %s"
                  % (server.ip.format(), proc.returncode and "down" or "up"))
        if proc.returncode == 0:
            server.status = cls.ICMP_UP_STATUS
        else:
            server.status = cls.ICMP_DOWN_STATUS
        return server

    def __eq__(self, other):
        if not isinstance(other, Host):
            raise TypeError("%s should be an instance of %s" % (
                other, Host.__class__.__name__))
        return self.ip == other.ip and self.status == other.status

    def __ne__(self, other):
        return not self.__eq__(other)


class VMScenario(nova_utils.NovaScenario, cinder_utils.CinderScenario):
    """Base class for VM scenarios with basic atomic actions.

    VM scenarios are scenarios executed inside some launched VM instance.
    """

    USER_RWX_OTHERS_RX_ACCESS_MODE = 0o755

    RESOURCE_NAME_PREFIX = "rally_vm_"

    @atomic.action_timer("vm.run_command_over_ssh")
    def _run_command_over_ssh(self, ssh, command):
        """Run command inside an instance.

        This is a separate function so that only script execution is timed.

        :param ssh: A SSHClient instance.
        :param command: Dictionary specifying command to execute.
            See `rally info find VMTasks.boot_runcommand_delete' parameter
            `command' docstring for explanation.

        :returns: tuple (exit_status, stdout, stderr)
        """
        validation.check_command_dict(command)

        # NOTE(pboldin): Here we `get' the values and not check for the keys
        # due to template-driven configuration generation that can leave keys
        # defined but values empty.
        if command.get("script_file") or command.get("script_inline"):
            cmd = command["interpreter"]
            if command.get("script_file"):
                stdin = open(command["script_file"], "rb")
            elif command.get("script_inline"):
                stdin = six.moves.StringIO(command["script_inline"])
        elif command.get("remote_path"):
            cmd = command["remote_path"]
            stdin = None

        if command.get("local_path"):
            remote_path = cmd[-1] if isinstance(cmd, (tuple, list)) else cmd
            ssh.put_file(command["local_path"], remote_path,
                         mode=self.USER_RWX_OTHERS_RX_ACCESS_MODE)

        if command.get("command_args"):
            if not isinstance(cmd, (list, tuple)):
                cmd = [cmd]
            # NOTE(pboldin): `ssh.execute' accepts either a string interpreted
            # as a command name or the list of strings that are converted into
            # single-line command with arguments.
            cmd = cmd + list(command["command_args"])

        return ssh.execute(cmd, stdin=stdin)

    def _boot_server_with_fip(self, image, flavor, use_floating_ip=True,
                              floating_network=None, **kwargs):
        """Boot server prepared for SSH actions."""
        kwargs["auto_assign_nic"] = True
        server = self._boot_server(image, flavor, **kwargs)

        if not server.networks:
            raise RuntimeError(
                "Server `%s' is not connected to any network. "
                "Use network context for auto-assigning networks "
                "or provide `nics' argument with specific net-id." %
                server.name)

        if use_floating_ip:
            fip = self._attach_floating_ip(server, floating_network)
        else:
            internal_network = list(server.networks)[0]
            fip = {"ip": server.addresses[internal_network][0]["addr"]}

        return server, {"ip": fip.get("ip"),
                        "id": fip.get("id"),
                        "is_floating": use_floating_ip}

    @atomic.action_timer("vm.attach_floating_ip")
    def _attach_floating_ip(self, server, floating_network):
        internal_network = list(server.networks)[0]
        fixed_ip = server.addresses[internal_network][0]["addr"]

        fip = network_wrapper.wrap(self.clients, self).create_floating_ip(
            ext_network=floating_network,
            tenant_id=server.tenant_id, fixed_ip=fixed_ip)

        self._associate_floating_ip(server, fip["ip"], fixed_address=fixed_ip,
                                    atomic_action=False)

        return fip

    @atomic.action_timer("vm.delete_floating_ip")
    def _delete_floating_ip(self, server, fip):
        with logging.ExceptionLogger(
                LOG, _("Unable to delete IP: %s") % fip["ip"]):
            if self.check_ip_address(fip["ip"])(server):
                self._dissociate_floating_ip(server, fip["ip"],
                                             atomic_action=False)
                network_wrapper.wrap(self.clients, self).delete_floating_ip(
                    fip["id"], wait=True)

    def _delete_server_with_fip(self, server, fip, force_delete=False):
        if fip["is_floating"]:
            self._delete_floating_ip(server, fip)
        return self._delete_server(server, force=force_delete)

    @atomic.action_timer("vm.wait_for_ssh")
    def _wait_for_ssh(self, ssh, timeout=120, interval=1):
        ssh.wait(timeout, interval)

    @atomic.action_timer("vm._wait_for_ping")
    def _wait_for_ping(self, server_ip):
        server = Host(server_ip)
        utils.wait_for_status(
            server,
            ready_statuses=[Host.ICMP_UP_STATUS],
            update_resource=Host.update_status,
            timeout=CONF.benchmark.vm_ping_timeout,
            check_interval=CONF.benchmark.vm_ping_poll_interval
        )

    def _run_command(self, server_ip, port, username, password, command,
                     pkey=None, timeout=120, interval=1):
        """Run command via SSH on server.

        Create SSH connection for server, wait for server to become available
        (there is a delay between server being set to ACTIVE and sshd being
        available). Then call run_command_over_ssh to actually execute the
        command.

        :param server_ip: server ip address
        :param port: ssh port for SSH connection
        :param username: str. ssh username for server
        :param password: Password for SSH authentication
        :param command: Dictionary specifying command to execute.
            See `rally info find VMTasks.boot_runcommand_delete' parameter
            `command' docstring for explanation.
        :param pkey: key for SSH authentication
        :param timeout: wait for ssh timeout. Default is 120 seconds
        :param interval: ssh retry interval. Default is 1 second

        :returns: tuple (exit_status, stdout, stderr)
        """
        pkey = pkey if pkey else self.context["user"]["keypair"]["private"]
        ssh = sshutils.SSH(username, server_ip, port=port,
                           pkey=pkey, password=password)
        self._wait_for_ssh(ssh, timeout, interval)
        return self._run_command_over_ssh(ssh, command)

    @staticmethod
    def _ping_ip_address(host):
        """Check ip address that it is pingable.

        :param host: instance of `netaddr.IPAddress`
        """
        ping = "ping" if host.version == 4 else "ping6"
        if sys.platform.startswith("linux"):
            cmd = [ping, "-c1", "-w1", str(host)]
        else:
            cmd = [ping, "-c1", str(host)]

        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        proc.wait()
        LOG.debug("Host %s is ICMP %s"
                  % (host, proc.returncode and "down" or "up"))
        return ICMP_UP_STATUS if (proc.returncode == 0) else ICMP_DOWN_STATUS

    @atomic.action_timer("vm.wait_for_ping")
    def _wait_for_ping_windows(self, server_ip):
        server_ip = netaddr.IPAddress(server_ip)
        utils.wait_for(
            server_ip,
            is_ready=utils.resource_is(ICMP_UP_STATUS, self._ping_ip_address),
            timeout=CONF.benchmark.vm_ping_timeout,
            check_interval=CONF.benchmark.vm_ping_poll_interval
        )
        utils.wait_for(
            server_ip,
            is_ready=utils.resource_is(ICMP_DOWN_STATUS,
                                       self._ping_ip_address),
            timeout=CONF.benchmark.vm_ping_timeout,
            check_interval=CONF.benchmark.vm_ping_poll_interval
        )
        utils.wait_for(
            server_ip,
            is_ready=utils.resource_is(ICMP_UP_STATUS, self._ping_ip_address),
            timeout=CONF.benchmark.vm_ping_timeout,
            check_interval=CONF.benchmark.vm_ping_poll_interval
        )

    @atomic.action_timer("vm.wait_for_ping")
    def _wait_for_ping_linux(self, server_ip):
        server_ip = netaddr.IPAddress(server_ip)
        utils.wait_for(
            server_ip,
            is_ready=utils.resource_is(ICMP_UP_STATUS, self._ping_ip_address),
            timeout=CONF.benchmark.vm_ping_timeout,
            check_interval=CONF.benchmark.vm_ping_poll_interval
        )

    @atomic.action_timer("vm.wait_for_hadoop_to_start")
    def _wait_for_hadoop_to_start(self, server_ip, username, os_distro,
                                  password=None, pkey=None, interval_retry=1,
                                  retry_count_total=10, port=22):

        if os_distro == 'windows':
            self.wait_for_hadoop_on_windows(server_ip, username, password,
                                            interval_retry, retry_count_total)
        else:
            self.wait_for_hadoop_on_ubuntu(server_ip, username, pkey, port)

    def wait_for_hadoop_on_ubuntu(self, server_ip, username, pkey, port):
        command = (
                    "sudo sed -i '0,/localhost/c\\127.0.0.1 "
                    "localhost %(hostname)s' /etc/hosts;"
                    "~/hadoop-2.7.1/bin/hdfs namenode -format;"
                    "~/hadoop-2.7.1/sbin/start-all.sh;"
                    "~/hadoop-2.7.1/bin/hdfs dfsadmin -safemode wait"
                  )

        ssh = sshutils.SSH(username, server_ip, port=port,
                           pkey=pkey, password=None)
        ssh.wait()

        _, hostname, _ = ssh.execute('hostname')
        code, out, err = ssh.execute(command % {'hostname': hostname})
        if code:
            raise Exception("Command failed! Check error: %s" % err)

    def wait_for_hadoop_on_windows(self, server_ip, username, password,
                                   interval_retry=1, retry_count_total=10):
        session = winrm.Session(server_ip, auth=(username, password),
                                transport='ssl')
        retry_count = retry_count_total
        while True:
            try:
                session.run_ps("ls")
                LOG.debug("WinRM is UP")
                break
            except Exception:
                if retry_count == 0:
                    raise
                retry_count = retry_count - 1
                LOG.debug("Winrm is down")
                time.sleep(interval_retry)

        retry_count = retry_count_total
        cmd_register_task = (
            'Start-Process powershell -wait -verb runas '
            '\'$dom = "$env:USERDOMAIN";$usr="$env:USERNAME";'
            '$Sta = New-ScheduledTaskAction -Execute "start-all.cmd";'
            'Register-ScheduledTask -TaskName "HadoopTest" -Action $Sta '
            '-User $dom\$usr -Password %s -RunLevel Highest\'' % password
            )
        LOG.debug(cmd_register_task)
        LOG.debug(session.run_ps(cmd_register_task).std_out)
        cmd = 'Start-ScheduledTask -TaskName "\HadoopTest"'
        while True:
            try:
                session.run_ps(cmd)
                LOG.debug("Hadoop starting...")
                break
            except Exception:
                if retry_count == 0:
                    raise
                retry_count = retry_count - 1
                LOG.debug("Winrm is down")
                time.sleep(interval_retry)

        retry_count = retry_count_total
        cmd = "hdfs dfsadmin -safemode wait"
        while True:
            try:
                output = session.run_ps(cmd)
                LOG.debug(output.std_out)
                LOG.debug(output.std_err)
                if output.std_err.find("Connection refused") < 0:
                    break
            except Exception:
                if retry_count == 0:
                    raise
                retry_count = retry_count - 1
                LOG.debug("Hadoop is not ready yet")
                time.sleep(interval_retry)

    def _run_job_winrm(self, job_idx, server_ip, username, password,
                       command, retry_count=3, interval=1):
        session = winrm.Session(server_ip, auth=(username, password),
                                transport='ssl')

        @atomic.action_timer("vm.job_execution_%s" % job_idx)
        def run(self):
            retry = retry_count
            success_filter = "completed successfully"
            while True:
                try:
                    LOG.debug("Running job: %s" % command)
                    result = session.run_ps(command)
                    LOG.debug(result.std_err)
                    if result.std_err.find(success_filter) < 0:
                        return False
                    LOG.debug("Job completed succesfully #%d" % job_idx)
                    return True
                except Exception:
                    if retry == 0:
                        raise
                    retry = retry - 1
                    time.sleep(interval)

        run(self)

    def _run_job_ssh(self, job_idx, server_ip, username, private_key,
                     command, retry_count=3, interval=1):
        ssh = sshutils.SSH(username, server_ip, port=22,
                           pkey=private_key, password=None)
        ssh.wait()

        @atomic.action_timer("vm.job_execution_%s" % job_idx)
        def run(self):
            retry = retry_count
            success_filter = "completed successfully"
            while True:
                try:
                    LOG.debug("Running job: %s" % command)
                    code, out, err = ssh.execute(command)
                    LOG.debug(err)
                    if err.find(success_filter) < 0:
                        return False
                    LOG.debug("Job completed succesfully #%d" % job_idx)
                    return True
                except Exception:
                    if retry == 0:
                        raise
                    retry = retry - 1
                    time.sleep(interval)

        run(self)
