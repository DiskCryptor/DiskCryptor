# DiskCryptor

DiskCryptor is an open source encryption solution that offers encryption of all disk partitions, including system partitions. DiskCryptor's openness is in sharp contrast with other encryption software today, where most of the software with comparable functionality is completely proprietary, making it unacceptable to use for protection of confidential data.

Originally DiskCryptor was developed as a replacement for DriveCrypt Plus Pack and PGP WDE by ntldr, however as he stopped since 2014 we decided to continue the development on our own here. 

We have updated DiskCryptor for use with Windows 10 and 11, adding a UEFI/GPT bootloader as well as other minor fixes to improve compatibility. We aim at further improving and maintaining compatibility with modern Windows versions.


## Program Features

</h2></td>
</tr>
<tr class="odd">
<td><ul>
<li><strong>Support of <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a>, <a href="https://en.wikipedia.org/wiki/Twofish">Twofish</a>, <a href="https://en.wikipedia.org/wiki/Serpent_(cipher)">Serpent</a> encryption algorithms</strong>, including their combinations.
<ul>
<li>Transparent encryption of disk partitions.</li>
<li>Full support for dynamic disks.</li>
<li>Support for disk devices with large sector size (important for <a href="https://en.wikipedia.org/wiki/RAID">hardware RAID</a> operation).</li>
</ul></li>
<li><strong>High performance</strong>, comparable to efficiency of a non-encrypted system.
<ul>
<li>Support for hardware AES acceleration:
<ul>
<li>AES New Instructions set on recent <a href="http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-instructions-aes-ni">Intel</a> and AMD CPUs;</li>
<li><a href="http://www.via.com.tw/en/initiatives/padlock/hardware.jsp">PadLock extensions</a> on VIA processors.</li>
</ul></li>
<li>Support for the SSD <a href="https://en.wikipedia.org/wiki/Trim_(computing)">TRIM</a> extension.</li>
</ul></li>
<li><strong>Broad choice in configuration of booting</strong> an encrypted OS. Support for various multi-boot options.
<ul>
<li>Full compatibility with <a href="https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface">UEFI</a>/<a href="https://en.wikipedia.org/wiki/GUID_Partition_Table">GPT</a> boot</li>
<li>MBR bootloader. Full compatibility with third party boot loaders (<a href="https://en.wikipedia.org/wiki/LILO_(boot_loader)">LILO</a>, <a href="https://en.wikipedia.org/wiki/GNU_GRUB">GRUB</a>, etc.).</li>
<li>Encryption of system partitions with pre-boot authentication.</li>
<li>Option to place boot loader on external media and to authenticate using the key media.</li>
<li>Support for key files.</li>
</ul></li>
<li><strong>Full support for external storage devices</strong>.
<ul>
<li>Option to create encrypted CD and DVD disks.</li>
<li>Full support for encryption of external USB storage devices.</li>
<li>Automatic mounting of disk partitions and external storage devices.</li>
</ul></li>
<li>Support for hot keys and optional command-line interface (CLI).</li>
<li><strong>Open license</strong> <a href="https://en.wikipedia.org/wiki/GNU_General_Public_License">GNU GPLv3</a>.</li>
</ul></td>
</tr>


## F.A.Q.

#### Is DiskCryptor still maintained? The last release was over a year ago.
Yes. DiskCryptor is still actively maintained. However, it is a very mature piece of software, and there is little ongoing development required. As a result, releases are infrequent.

#### All DiskCryptor builds are labeled "BETA" Will there ever be a FINAL release?
No. The BETA label for now is intentional and serves as an explicit warning. DiskCryptor is a free, low-level disk encryption tool; even minor misuse, misconfiguration, or unexpected interactions can result in irreversible data loss.

The BETA designation serves as a clear warning and a legal and practical boundary: you are expected to understand what the software does and to assume full responsibility for its use. __DiskCryptor is used entirely at your own risk.__

We might adjust the statement in the future, though.

I have personally used DiskCryptor for decades without major issues; however, I understand the implications of each action and always maintain reliable backups.

#### I installed a Windows update and the DiskCryptor bootloader no longer starts. Windows boots directly into recovery. What should I do?

This typically occurs when the EFI firmware is configured to boot ```\EFI\Microsoft\Boot\bootmgfw.efi``` instead of ```\EFI\DCS\DcsBoot.efi```.
In this configuration, DiskCryptor replaces bootmgfw.efi with its own bootloader. A Windows update may restore the original Microsoft bootloader, which breaks the DiskCryptor boot chain. To resolve this, you must replace the file again.

Recovery procedure (from Windows Recovery Environment):
1. Boot into WinRE and open a Command Prompt.
2. Mount the EFI system partition: ```mountvol S: /S```
3. Create a new file: ```S:\EFI\DCS\fix_dcs.cmd``` add the following contents to the file:
```
cd \EFI\Microsoft\Boot
del bootmgfw_ms.vc.old 
ren bootmgfw_ms.vc bootmgfw_ms.vc.old 
ren bootmgfw.efi bootmgfw_ms.vc
copy ..\..\DCS\DcsBoot.efi bootmgfw.efi
```
4. Execute the script to restore the DiskCryptor bootloader. Alternatively, you may run the commands manually one by one.
5. Reboot.

This issue may reoccur after future Windows updates. Keeping this script available allows for quick recovery.
For a permanent solution, review and correct your EFI boot order so that the system boots \EFI\DCS\DcsBoot.efi directly.

#### Does DiskCryptor support Secure Boot?
DiskCryptor offers Secure Boot support using a SHIM mechanism with a custom MOK, its simple to set up and works on all systems on which linux secure boot also works.

[More F.A.Q. on the Home Page](https://diskcryptor.org/faq/)

