S_LOCAL_PATH := $(call my-dir)

ifneq ($(filter VER_0_8_X VER_2_1_DEVEL,$(WPA_SUPPLICANT_VERSION)),)
# The order of the 2 Android.mks does matter!
# TODO: Clean up the Android.mks, reset all the temporary variables at the
# end of each Android.mk, so that one Android.mk doesn't depend on variables
# set up in the other Android.mk.
include $(S_LOCAL_PATH)/hostapd/Android.mk \
        $(S_LOCAL_PATH)/wpa_supplicant/Android.mk
ifneq ($(TARGET_BUILD_VARIANT), user)
ifeq ($(shell test $(PLATFORM_VERSION_LAST_STABLE) -ge 8 ; echo $$?), 0)
include $(S_LOCAL_PATH)/hs20/client/Android.mk
endif #End of Check for platform version
endif #End of Check for target build variant
endif
