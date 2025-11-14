# OpenWrt package for l2shell
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=l2shell
PKG_RELEASE:=1
PKG_VERSION:=1.0.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_PARALLEL:=1

define Package/l2shell
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Layer-2 shell client and server
  URL:=https://github.com/legale/l2shell
endef

define Package/l2shell/description
Layer-2 shell utilities a - server, b - client and kernel module trigger.
endef

define KernelPackage/l2shell-kmod
  SUBMENU:=Network Support
  SECTION:=net
  CATEGORY:=Kernel modules
  TITLE:=l2shell kernel trigger
  VERSION:=$(LINUX_VERSION)-$(PKG_VERSION)-$(PKG_RELEASE)
  FILES:=$(PKG_BUILD_DIR)/l2shell_kmod.$(LINUX_KMOD_SUFFIX)
  AUTOLOAD:=$(call AutoLoad,50,l2shell_kmod)
endef

define KernelPackage/l2shell-kmod/description
Kernel trigger launches the userland server.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ../../src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		KDIR="$(LINUX_DIR)" \
		CC="$(TARGET_CC)" \
		LD="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		BIN_A=a BIN_B=b


	# kernel module l2shell_kmod.ko
	$(KERNEL_MAKE) \
		M="$(PKG_BUILD_DIR)" \
		modules
endef

define Package/l2shell/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/a $(1)/usr/bin/a
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/b $(1)/usr/bin/b
endef


define KernelPackage/l2shell-kmod/install
	# no extra files apart from the module itself
	true
endef

$(eval $(call BuildPackage,l2shell))
$(eval $(call KernelPackage,l2shell-kmod))
