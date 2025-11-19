# Two hypervisors will walk into a kernel

If like me, you run `libvirtd` (the daemon that manages KVM/QEMU), and you wish to do the RIPE labs, you need to turn it off so that VirtualBox can grab `VT-x/AMD-V` without screaming at you.

## Stop KVM/libvirt services (for VirtualBox)

On a `systemd`-based distro (Ubuntu, Fedora, Debian, Arch, etc.):

```bash
# Stop the libvirt daemon and logging services
sudo systemctl stop libvirtd
sudo systemctl stop virtlogd

# Stop libvirt socket units to prevent automatic restarting
sudo systemctl stop libvirtd.socket libvirtd-admin.socket libvirtd-ro.socket
sudo systemctl stop virtlogd.socket virtlogd-admin.socket

# Stop the default libvirt network(s) to release dnsmasq
sudo virsh net-destroy default 2>/dev/null || true

# Kill any leftover dnsmasq instances from libvirt
sudo pkill -f '/usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq' || true

# Verify no libvirt/QEMU/dnsmasq processes remain
ps aux | grep -E 'qemu|kvm|libvirt|dnsmasq'
````

Explanation:

* `libvirtd` is the main daemon managing KVM/QEMU.
* `virtlogd` handles VM logging.
* Socket units auto-start services when something connects; stopping them prevents auto-restart.
* `virsh net-destroy default` stops the virtual network that spawns `dnsmasq`, which otherwise keeps VT-x/AMD-V busy.
* `pkill` ensures any lingering `dnsmasq` processes are terminated.
* `ps aux | grep ...` confirms everything is stopped.

---

## Restart KVM/libvirt services (after using VirtualBox)

```bash
# Start libvirt services
sudo systemctl start libvirtd
sudo systemctl start virtlogd

# Start socket units
sudo systemctl start libvirtd.socket libvirtd-admin.socket libvirtd-ro.socket
sudo systemctl start virtlogd.socket virtlogd-admin.socket

# Start and auto-enable the default network
sudo virsh net-start default 2>/dev/null || true
sudo virsh net-autostart default 2>/dev/null || true

# Verify services are running
ps aux | grep -E 'qemu|kvm|libvirt|dnsmasq'
```

Explanation:

* Restores full KVM/libvirt functionality.
* `net-autostart` ensures the network comes back after a reboot.

---

## Toggle script

```bash
#!/bin/bash
# vm-switch.sh - toggle between VirtualBox and virt-manager (KVM/libvirt)
# Usage: ./vm-switch.sh {vbox|kvm|status}

# Helper function to stop libvirt services safely
stop_libvirt() {
    echo "[*] Stopping libvirt services..."
    sudo systemctl stop libvirtd virtlogd
    sudo systemctl stop libvirtd.socket libvirtd-admin.socket libvirtd-ro.socket
    sudo systemctl stop virtlogd.socket virtlogd-admin.socket
    # Stop default network if active
    if virsh net-info default &>/dev/null; then
        sudo virsh net-destroy default
    fi
    # Kill any lingering dnsmasq from libvirt
    sudo pkill -f '/usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq' || true
}

# Helper function to start libvirt services safely
start_libvirt() {
    echo "[*] Starting libvirt services..."
    sudo systemctl start libvirtd virtlogd
    sudo systemctl start libvirtd.socket libvirtd-admin.socket libvirtd-ro.socket
    sudo systemctl start virtlogd.socket virtlogd-admin.socket
    # Restore default network
    if ! virsh net-info default &>/dev/null; then
        sudo virsh net-start default 2>/dev/null || true
        sudo virsh net-autostart default 2>/dev/null || true
    fi
}

case "$1" in
    vbox)
        echo "[*] Switching to VirtualBox mode..."
        stop_libvirt
        # Remove KVM modules if loaded
        if lsmod | grep -q '^kvm'; then
            echo "[*] Unloading KVM kernel modules..."
            sudo modprobe -r kvm_intel kvm_amd 2>/dev/null || true
        fi
        echo "[+] System ready for VirtualBox"
        ;;

    kvm)
        echo "[*] Switching to virt-manager (KVM) mode..."
        # Load KVM modules if not loaded
        if ! lsmod | grep -q '^kvm'; then
            echo "[*] Loading KVM kernel modules..."
            sudo modprobe kvm_intel 2>/dev/null || sudo modprobe kvm_amd 2>/dev/null || true
        fi
        start_libvirt
        echo "[+] System ready for virt-manager"
        ;;

    status)
        echo "[*] libvirtd service status:"
        systemctl is-active libvirtd
        echo "[*] KVM kernel modules loaded:"
        lsmod | grep kvm || echo "None"
        echo "[*] Default network state:"
        virsh net-info default 2>/dev/null || echo "No default network"
        ;;

    *)
        echo "Usage: $0 {vbox|kvm|status}"
        ;;
esac
```

### What this script does and does not do

The script only handles switching the KVM/libvirt side, it does not start or stop VirtualBox itself. That is usually 
fine because VirtualBox runs its own daemon (`vboxdrv`) and GUI (`VirtualBox`) independently.

A few clarifications:

1. VirtualBox does not need a daemon to be stopped/started like libvirt. It will only complain if KVM/libvirt has grabbed VT-x/AMD-V.
2. Once you’ve run `./vm-switch.sh vbox`, your system is clear for VirtualBox. You just open VirtualBox normally.
3. When you’re done with VirtualBox and want to use `virt-manager`, run `./vm-switch.sh kvm`. This will:

   * Start libvirt/virtlogd.
   * Reload KVM modules.
   * Restore the default virtual network.

So the “start/stop VirtualBox” part is manual: you launch the VirtualBox GUI or VM after clearing libvirt, and close it before switching back to KVM.

### Save the script

1. Open a terminal.
2. Navigate to a directory to keep the script:

```bash
cd ~/bin
```

3. Create the script:

```bash
nano vm-switch.sh
```

4. Paste the full script content.
5. Save and exit.

---

### Make it executable

```bash
chmod +x vm-switch.sh
```

Now you can run it like a normal command.

---

### Optional: Add to your PATH

```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

### Usage

Switch to VirtualBox mode (stops libvirt/KVM services and unloads modules):

```bash
./vm-switch.sh vbox
```

Start libvirt services and loads modules:

```bash
./vm-switch.sh kvm
```

Check current status:

```bash
./vm-switch.sh status
```

Shows:

* Whether `libvirtd` is active
* Which KVM modules are loaded
* Default network state

---

### Notes & safety

* Always check `status` if unsure.
* The script handles virtual networks (`dnsmasq`) automatically.
* Safe to run repeatedly. Modules and services are only started/stopped as necessary.
* No need to touch VirtualBox or virt-manager settings; the script manages the backend cleanly.

