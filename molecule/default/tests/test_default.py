import os
import pytest
import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

# "* Applying /etc/sysctl.d/10-bossjones.conf ...",
# "kernel.shmall=505599",
# "kernel.shmmax=828373402",
# "net.ipv4.conf.all.rp_filter=1",
# "net.ipv4.conf.default.rp_filter=1",
# "net.ipv4.icmp_echo_ignore_broadcasts=1",
# "net.ipv4.icmp_ignore_bogus_error_responses=1",
# "net.ipv4.icmp_ratelimit=100",
# "net.ipv4.icmp_ratemask=88089",
# "net.ipv4.ip_forward=0",
# "net.ipv6.conf.all.accept_ra=0",
# "net.ipv6.conf.all.forwarding=0",
# "net.ipv6.conf.default.accept_ra=0",
# "vm.swappiness=60",
# "vm.vfs_cache_pressure=100",
# "* Applying /etc/sysctl.d/10-console-messages.conf ...",
# "kernel.printk=4 4 1 7",
# "* Applying /etc/sysctl.d/10-ipv6-privacy.conf ...",
# "net.ipv6.conf.all.use_tempaddr=2",
# "net.ipv6.conf.default.use_tempaddr=2",
# "* Applying /etc/sysctl.d/10-kernel-hardening.conf ...",
# "kernel.kptr_restrict=1",
# "* Applying /etc/sysctl.d/10-link-restrictions.conf ...",
# "fs.protected_hardlinks=1",
# "fs.protected_symlinks=1",
# "* Applying /etc/sysctl.d/10-magic-sysrq.conf ...",
# "kernel.sysrq=176",
# "* Applying /etc/sysctl.d/10-network-security.conf ...",
# "net.ipv4.conf.default.rp_filter=1",
# "net.ipv4.conf.all.rp_filter=1",
# "* Applying /etc/sysctl.d/10-ptrace.conf ...",
# "* Applying /etc/sysctl.d/10-zeropage.conf ...",
# "vm.mmap_min_addr=65536",
# "* Applying /etc/sysctl.d/99-sysctl.conf ...",
# "* Applying /etc/sysctl.conf ..."


# root@boss-ansible-role-sysctl-trusty:/etc/sysctl.d# cat 10-bossjones.conf
# # Ansible managed: Do NOT edit this file manually!

# kernel.shmall = 505599
# kernel.shmmax = 828373402
# # Enable RFC-recommended source validation feature.
# net.ipv4.conf.all.rp_filter = 1
# # Enable RFC-recommended source validation feature.
# net.ipv4.conf.default.rp_filter = 1
# # Reduce the surface on SMURF attacks.
# # Make sure to ignore ECHO broadcasts, which are only required in broad network analysis.
# net.ipv4.icmp_echo_ignore_broadcasts = 1
# # There is no reason to accept bogus error responses from ICMP, so ignore them instead.
# net.ipv4.icmp_ignore_bogus_error_responses = 1
# # Limit the amount of traffic the system uses for ICMP.
# net.ipv4.icmp_ratelimit = 100
# # Adjust the ICMP ratelimit to include ping, dst unreachable,
# # source quench, ime exceed, param problem, timestamp reply, information reply
# net.ipv4.icmp_ratemask = 88089
# # Disable IPv4 traffic forwarding.
# net.ipv4.ip_forward = 0
# # RFC 1337 fix F1.
# net.ipv4.tcp_rfc1337 = 1
# # Protect against wrapping sequence numbers at gigabit speeds.
# net.ipv4.tcp_timestamps = 0
# # Ignore IPv6 RAs.
# net.ipv6.conf.all.accept_ra = 0
# # Disable IPv6 traffic forwarding.
# net.ipv6.conf.all.forwarding = 0
# # Ignore IPv6 RAs.
# net.ipv6.conf.default.accept_ra = 0
# # How aggressively the kernel swaps out anonymous memory relative to pagecache and other caches.
# vm.swappiness = 60
# # Tendency of the kernel to reclaim the memory which is used for caching of VFS caches, versus pagecache and swap.
# vm.vfs_cache_pressure = 100

@pytest.mark.parametrize('f',
                         ["net.core.somaxconn = 16384",
                          "net.ipv4.ip_local_port_range = 1024 65535"])
def test_sysctl_bossjones(host, f):
    kern_values = host.file("/etc/sysctl.d/10-bossjones.conf")
    assert kern_values.contains(f)
    assert kern_values.user == "root"
    assert kern_values.group == "root"
    assert kern_values.mode == 0o644


# @pytest.mark.parametrize('f',
#                          ["kernel.printk = 4 4 1 7"])
# def test_console_messages(host, f):
#     kern_values = host.file("/etc/sysctl.d/10-console-messages.conf")
#     assert kern_values.contains(f)
#     assert kern_values.user == "root"
#     assert kern_values.group == "root"
#     assert kern_values.mode == 0o644


# @pytest.mark.parametrize('f',
#                          ["net.ipv6.conf.all.use_tempaddr = 2",
#                           "net.ipv6.conf.default.use_tempaddr = 2"])
# def test_kern_privacy(host, f):
#     kern_values = host.file("/etc/sysctl.d/10-ipv6-privacy.conf")
#     assert kern_values.contains(f)
#     assert kern_values.user == "root"
#     assert kern_values.group == "root"
#     assert kern_values.mode == 0o644

# @pytest.mark.parametrize('f',
#                          ["kernel.printk = 4 4 1 7"])
# def test_kern_hardening(host, f):
#     kern_values = host.file("/etc/sysctl.d/10-console-messages.conf")
#     assert kern_values.contains(f)
#     assert kern_values.user == "root"
#     assert kern_values.group == "root"
#     assert kern_values.mode == 0o644
