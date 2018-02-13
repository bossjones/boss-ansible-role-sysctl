import os
import pytest
import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')

# "* Applying /etc/sysctl.d/10-bossjones_sysctl.conf ...",
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


@pytest.mark.parametrize('f',
                         ["kernel.shmall=505599",
                          "kernel.shmmax=828373402",
                          "net.ipv4.conf.all.rp_filter=1",
                          "net.ipv4.conf.default.rp_filter=1",
                          "net.ipv4.icmp_echo_ignore_broadcasts=1",
                          "net.ipv4.icmp_ignore_bogus_error_responses=1",
                          "net.ipv4.icmp_ratelimit=100",
                          "net.ipv4.icmp_ratemask=88089",
                          "net.ipv4.ip_forward=0",
                          "net.ipv6.conf.all.accept_ra=0",
                          "net.ipv6.conf.all.forwarding=0",
                          "net.ipv6.conf.default.accept_ra=0",
                          "vm.swappiness=60",
                          "vm.vfs_cache_pressure=100"])
def test_sysctl_bossjones(host, f):
    kern_values = host.file("/etc/sysctl.d/10-bossjones_sysctl.conf")
    assert kern_values.contains(f)
    assert kern_values.user == "root"
    assert kern_values.group == "root"
    assert kern_values.mode == 0o644


@pytest.mark.parametrize('f',
                         ["kernel.printk=4 4 1 7"])
def test_console_messages(host, f):
    kern_values = host.file("/etc/sysctl.d/10-console-messages.conf")
    assert kern_values.contains(f)
    assert kern_values.user == "root"
    assert kern_values.group == "root"
    assert kern_values.mode == 0o644


@pytest.mark.parametrize('f',
                         ["net.ipv6.conf.all.use_tempaddr=2",
                          "net.ipv6.conf.default.use_tempaddr=2"])
def test_kern_privacy(host, f):
    kern_values = host.file("/etc/sysctl.d/10-ipv6-privacy.conf")
    assert kern_values.contains(f)
    assert kern_values.user == "root"
    assert kern_values.group == "root"
    assert kern_values.mode == 0o644

@pytest.mark.parametrize('f',
                         ["kernel.printk=4 4 1 7"])
def test_kern_hardening(host, f):
    kern_values = host.file("/etc/sysctl.d/10-console-messages.conf")
    assert kern_values.contains(f)
    assert kern_values.user == "root"
    assert kern_values.group == "root"
    assert kern_values.mode == 0o644
