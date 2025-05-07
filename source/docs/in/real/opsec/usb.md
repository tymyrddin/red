# USB key drop

## Attack tree

```text
1 Configure a script or application to automatically run when a USB drive is connected (AND)
    1.1 Collect information, for example IP address, of the system the drive is connected to (AND)
    1.2 Send the information to an
        1.2.1 Email address (OR)
        1.2.2 C2
2 Leave configured USB flash drives all over the organisation for someone to pick it up and plug it in
```

## Notes

* With USB key drop, you can find out the security awareness level of the organisation. If you leave ten USB drives, 
and you get eight email messages, it is clear to people they should not connect untrusted devices to their computers.

## Tools

* [USB Rubber Ducky](https://hak5.org/products/usb-rubber-ducky?variant=353378649)
* [Bash Bunny](https://hak5.org/products/bash-bunny)