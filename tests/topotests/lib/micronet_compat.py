# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 11 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
import logging
import os
import subprocess
import traceback

from lib.micronet import LinuxNamespace, Micronet
from lib.micronet_cli import cli


class Node(LinuxNamespace):
    """Node (mininet compat)."""

    def __init__(self, name, **kwargs):
        """
        Create a Node.
        """
        self.params = kwargs

        if "private_mounts" in kwargs:
            private_mounts = kwargs["private_mounts"]
        else:
            private_mounts = kwargs.get("privateDirs", [])

        logger = kwargs.get("logger")

        super(Node, self).__init__(name, logger=logger, private_mounts=private_mounts)

    def cmd(self, cmd, **kwargs):
        """Execute a command, joins stdout, stderr, ignores exit status."""

        return super(Node, self).cmd_legacy(cmd, **kwargs)

    def config(self, lo="up", **params):
        """Called by Micronet when topology is built (but not started)."""
        # mininet brings up loopback here.
        del params
        del lo

    def intfNames(self):
        return self.intfs

    def terminate(self):
        return


class Topo(object):  # pylint: disable=R0205
    def __init__(self, *args, **kwargs):
        raise Exception("Remove Me")


class Mininet(Micronet):
    """
    Mininet using Micronet.
    """

    g_mnet_inst = None

    def __init__(self, controller=None):
        """
        Create a Micronet.
        """
        assert not controller

        if Mininet.g_mnet_inst is not None:
            Mininet.g_mnet_inst.stop()
        Mininet.g_mnet_inst = self

        self.configured_hosts = set()
        self.host_params = {}
        self.prefix_len = 8

        # SNMPd used to require this, which was set int he mininet shell
        # that all commands executed from. This is goofy default so let's not
        # do it if we don't have to. The snmpd.conf files have been updated
        # to set permissions to root:frr 770 to make this unneeded in that case
        # os.umask(0)

        super(Mininet, self).__init__()

        self.logger.debug("%s: Creating", self)

    def __str__(self):
        return "Mininet()"

    def configure_hosts(self):
        """
        Configure hosts once the topology has been built.

        This function can be called multiple times if routers are added to the topology
        later.
        """
        if not self.hosts:
            return

        self.logger.debug("Configuring hosts: %s", self.hosts.keys())

        for name in sorted(self.hosts.keys()):
            if name in self.configured_hosts:
                continue

            host = self.hosts[name]
            first_intf = host.intfs[0] if host.intfs else None
            params = self.host_params[name]

            if first_intf and "ip" in params:
                ip = params["ip"]
                i = ip.find("/")
                if i == -1:
                    plen = self.prefix_len
                else:
                    plen = int(ip[i + 1 :])
                    ip = ip[:i]

                host.cmd("ip addr add {}/{} dev {}".format(ip, plen, first_intf))

            if "defaultRoute" in params:
                host.cmd("ip route add default {}".format(params["defaultRoute"]))

            host.config()

            self.configured_hosts.add(name)

    def add_host(self, name, cls=Node, **kwargs):
        """Add a host to micronet."""

        self.host_params[name] = kwargs
        super(Mininet, self).add_host(name, cls=cls, **kwargs)

    def start(self):
        """Start the micronet topology."""
        self.logger.debug("%s: Starting (no-op).", self)

    def stop(self):
        """Stop the mininet topology (deletes)."""
        self.logger.debug("%s: Stopping (deleting).", self)

        self.delete()

        self.logger.debug("%s: Stopped (deleted).", self)

        if Mininet.g_mnet_inst == self:
            Mininet.g_mnet_inst = None

    def cli(self):
        cli(self)
