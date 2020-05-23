.PHONY: FORCE
all: FORCE
	$(MAKE) -C .. ghost_qt test_ghost_qt
clean: FORCE
	$(MAKE) -C .. ghost_qt_clean test_ghost_qt_clean
check: FORCE
	$(MAKE) -C .. test_ghost_qt_check
bitcoin-qt bitcoin-qt.exe: FORCE
	 $(MAKE) -C .. ghost_qt
