# Dependencies

The framework uses `hostap` and `libwifi` as dependencies.

For more information on its setup, see the [installation and configuration instructions](../setup/README.md).

## Hostap

We provide ```hostap``` (Version 2.10) which includes the modifications and extensions for our framework.

If you want to inspect all the applied modifications, then you can execute:
```
git clone -b 'hostap_2_10' --single-branch --depth 1 git://w1.fi/srv/git/hostap.git hostap_2_10_original
diff -ur hostap_2_10_original/ hostap_2_10/ -x '*.d' -x '*.o' -x '*.service' | grep -v "Only in" > diff.patch
```

Remarks:
- the file `wpaspy.py` in the `dependencies` directory is a symbolic link to the `wpaspy.py` module of `hostap`.
  This is done to make it easier to import the `wpaspy` module in python.
- In hostapd 2.10, the control interface message `AP-STA-ASSOCIATING` is now sent when executing `handle_assoc`
  instead of at the end of `handle_auth`.


## Libwifi

[Libwifi](https://github.com/vanhoefm/libwifi) is an experimental library offering an implementation for common Wi-Fi functionality.

The library is used often in our framework, and can be pulled using the following commands:
```
git submodule init
git submodule update
```

