ID := dev.khcrysalis.PlumeImpactor
ifeq ($(OS),Windows_NT)
OS := windows
# TODO: i don't know how to get this on windows
ARCH ?= x86_64
else
ARCH = $(shell uname -m)
ifeq ($(shell uname -s),Linux)
OS := linux
endif
ifeq ($(shell uname -s),Darwin)
OS := macos
endif
endif
PROFILE ?= debug
PREFIX ?= /usr/local
SUFFIX ?= $(OS)-$(ARCH)

BUNDLE ?= 0
BIN1 ?=
BIN2 ?=

APPIMAGE ?= 0
APPIMAGE_APPDIR ?= /tmp/AppDir

NSIS ?= 0

FLATPAK ?= 0
FLATPAK_BUILDER_TOOLS ?= /tmp/flatpak-builder-tools/
FLATPAK_BUILDER_TOOLS_COMMIT ?= 3fc0620788a1dda1a3a539b8f972edadce8260ab
FLATPAK_SHARED_MODULES ?= ./shared-modules/
FLATPAK_SHARED_MODULES_COMMIT ?= d1a2cf59d137b47abc07297ecd35a5af9b5e16f4
FLATPAK_BUILDER_DIR ?= ./.flatpak-out/
FLATPAK_BUILDER_MANIFEST ?= $(ID).json
FLATPAK_BUNDLE_REPO ?= ~/.local/share/flatpak/repo
FLATPAK_BUNDLE_FILENAME ?= Impactor-$(SUFFIX).flatpak
FLATPAK_BUNDLE_NAME ?= $(ID)

clean:
	@rm -rf ./dist
	@rm -rf ./build
	@rm -rf ./.flatpak-builder
	@rm -rf $(FLATPAK_BUILDER_DIR)

macos:
	@mkdir -p dist
ifeq ($(and $(BIN1),$(BIN2)),)
	@cargo build --bins --workspace --$(PROFILE)
	@cp target/$(PROFILE)/plumeimpactor dist/plumeimpactor-$(SUFFIX)
	@cp target/$(PROFILE)/plumesign dist/plumesign-$(SUFFIX)
else
	@name=$$(basename $(BIN1)); \
	name=$${name%-$(OS)-*}; \
	lipo -create -output dist/$${name}-$(SUFFIX) $(BIN1) $(BIN2)
endif
ifeq ($(BUNDLE),1)
	@cp -R package/macos/Impactor.app dist/Impactor.app
	@vtool -arch x86_64 -arch arm64 -set-build-version 1 10.12 26.0 -output dist/plumeimpactor-$(SUFFIX) dist/plumeimpactor-$(SUFFIX)
	@cp dist/plumeimpactor-$(SUFFIX) dist/Impactor.app/Contents/MacOS/Impactor
	@chmod +x dist/Impactor.app/Contents/MacOS/Impactor
	@strip dist/Impactor.app/Contents/MacOS/Impactor
	@VERSION=$$(awk '/\[workspace.package\]/,/^$$/' Cargo.toml | sed -nE 's/version *= *"([^"]*)".*/\1/p'); \
		/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $$VERSION" ./dist/Impactor.app/Contents/Info.plist; \
		/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $$VERSION" ./dist/Impactor.app/Contents/Info.plist
endif

linux:
ifeq ($(FLATPAK),1)
ifeq ($(wildcard $(FLATPAK_BUILDER_TOOLS)),)
	@git clone https://github.com/flatpak/flatpak-builder-tools.git "$(FLATPAK_BUILDER_TOOLS)"
	@cd $(FLATPAK_BUILDER_TOOLS); \
		git checkout $(FLATPAK_BUILDER_TOOLS_COMMIT)
endif
ifeq ($(wildcard $(FLATPAK_SHARED_MODULES)),)
	@git clone https://github.com/flathub/shared-modules.git "$(FLATPAK_SHARED_MODULES)"
	@cd $(FLATPAK_SHARED_MODULES); \
		git checkout $(FLATPAK_SHARED_MODULES_COMMIT)
endif
	@poetry --project "$(FLATPAK_BUILDER_TOOLS)/cargo" install
	@poetry --project "$(FLATPAK_BUILDER_TOOLS)/cargo" run \
		python "$(FLATPAK_BUILDER_TOOLS)/cargo/flatpak-cargo-generator.py" Cargo.lock -o package/linux/cargo-sources.json
	@flatpak-builder --ccache --force-clean --user --install $(FLATPAK_BUILDER_DIR) "package/linux/$(FLATPAK_BUILDER_MANIFEST)"
	@mkdir -p dist
	@cd package/linux; \
		flatpak build-bundle $(FLATPAK_BUNDLE_REPO) $(FLATPAK_BUNDLE_FILENAME) $(FLATPAK_BUNDLE_NAME)
	@cp package/linux/$(FLATPAK_BUNDLE_FILENAME) ./dist/$(FLATPAK_BUNDLE_FILENAME)
	@rm package/linux/$(FLATPAK_BUNDLE_FILENAME)
endif
	@cargo build --bins --workspace --$(PROFILE)
	@mkdir -p dist
	@cp target/$(PROFILE)/plumeimpactor ./dist/Impactor-$(SUFFIX)
	@cp target/$(PROFILE)/plumesign ./dist/plumesign-$(SUFFIX)
	@strip dist/Impactor-$(SUFFIX)
ifeq ($(APPIMAGE),1)
	@wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-$(ARCH).AppImage -O /tmp/linuxdeploy.appimage
	@chmod +x /tmp/linuxdeploy.appimage
	@make install PREFIX=$(APPIMAGE_APPDIR)/usr
	@lib_args=""; \
		for lib in \
			libayatana-appindicator3.so.1 \
			libappindicator3.so.1 \
			libayatana-ido3-0.4.so.0 \
			libdbusmenu-glib.so.4 \
			libdbusmenu-gtk3.so.4; do \
			path=""; \
			if command -v ldconfig >/dev/null 2>&1; then \
				path=$$(ldconfig -p 2>/dev/null | awk -v lib="$$lib" '$$1==lib {print $$NF; exit}'); \
			fi; \
			if [ -z "$$path" ]; then \
				for dir in /usr/lib /usr/lib64 /lib /lib64 /usr/lib/$(ARCH)-linux-gnu /usr/lib/x86_64-linux-gnu; do \
					if [ -e "$$dir/$$lib" ]; then path="$$dir/$$lib"; break; fi; \
				done; \
			fi; \
			if [ -n "$$path" ]; then \
				lib_args="$$lib_args --library $$path"; \
			elif [ "$$lib" = "libayatana-appindicator3.so.1" ] || [ "$$lib" = "libappindicator3.so.1" ]; then \
				echo "warning: $$lib not found; AppImage tray icon may fail to load"; \
			fi; \
		done; \
		NO_STRIP=true \
		/tmp/linuxdeploy.appimage --appimage-extract-and-run \
			--appdir $(APPIMAGE_APPDIR) \
			--executable target/$(PROFILE)/plumeimpactor \
			--desktop-file package/linux/$(ID).desktop \
			--exclude-library='libglib-2.0.so*' \
			--exclude-library='libgobject-2.0.so*' \
			--exclude-library='libgio-2.0.so*' \
			--exclude-library='libgmodule-2.0.so*' \
			--exclude-library='libgthread-2.0.so*' \
			--exclude-library='libxkbcommon.so*' \
			--exclude-library='libxkbcommon-x11.so*' \
			--exclude-library='libX11.so*' \
			--exclude-library='libxcb.so*' \
			$$lib_args \
			--output appimage
	@rm /tmp/linuxdeploy.appimage
	@mv Plume_Impactor-$(ARCH).AppImage dist/Impactor-$(SUFFIX).appimage
	@rm -rf $(APPIMAGE_APPDIR)
endif

windows:
	@cargo build --bins --workspace --$(PROFILE)
	@mkdir -p dist
	@mkdir -p dist/nsis
	@cp target/$(PROFILE)/plumesign.exe dist/plumesign-$(SUFFIX).exe
	@cp target/$(PROFILE)/plumeimpactor.exe dist/Impactor-$(SUFFIX)-portable.exe
ifeq ($(NSIS),1)
	@cp target/$(PROFILE)/plumeimpactor.exe dist/nsis/
	@cp -r package/windows/* dist/nsis/
	@VERSION=$$(awk '/\[workspace.package\]/,/^$$/' Cargo.toml | sed -nE 's/version *= *"([^"]*)".*/\1/p'); \
		makensis -DAPPVERSION=$$VERSION dist/nsis/installer.nsi
	@mv dist/nsis/installer.exe dist/Impactor-$(SUFFIX)-setup.exe
endif

install:
ifeq ($(OS),linux)
ifneq ($(PREFIX),$(APPIMAGE_APPDIR)/usr)
	@install -Dm755 target/$(PROFILE)/plumesign $(PREFIX)/bin/plumesign
	@install -Dm755 target/$(PROFILE)/plumeimpactor $(PREFIX)/bin/plumeimpactor
endif
	@install -Dm644 package/linux/$(ID).desktop $(PREFIX)/share/applications/$(ID).desktop
	@install -Dm644 package/linux/icons/hicolor/16x16/apps/$(ID).png $(PREFIX)/share/icons/hicolor/16x16/apps/$(ID).png
	@install -Dm644 package/linux/icons/hicolor/32x32/apps/$(ID).png $(PREFIX)/share/icons/hicolor/32x32/apps/$(ID).png
	@install -Dm644 package/linux/icons/hicolor/48x48/apps/$(ID).png $(PREFIX)/share/icons/hicolor/48x48/apps/$(ID).png
	@install -Dm644 package/linux/icons/hicolor/64x64/apps/$(ID).png $(PREFIX)/share/icons/hicolor/64x64/apps/$(ID).png
	@install -Dm644 package/linux/icons/hicolor/128x128/apps/$(ID).png $(PREFIX)/share/icons/hicolor/128x128/apps/$(ID).png
	@install -Dm644 package/linux/icons/hicolor/256x256/apps/$(ID).png $(PREFIX)/share/icons/hicolor/256x256/apps/$(ID).png
	@install -Dm644 package/linux/icons/hicolor/512x512/apps/$(ID).png $(PREFIX)/share/icons/hicolor/512x512/apps/$(ID).png
endif
ifeq ($(OS),darwin)
	@cp -r ./dist/Impactor.app $(PREFIX)/Impactor.app
endif
