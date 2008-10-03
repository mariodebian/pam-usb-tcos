all:
	cd po && make

clean:
	rm -f *~ *.gladep *bak
	cd po && make clean

install:
	mkdir -p $(DESTDIR)/usr/sbin/
	install -m 755 pamusb-conf-gui $(DESTDIR)/usr/sbin/

	
	mkdir -p $(DESTDIR)/usr/share/pamusb-tools-tcos/
	install -m 644 pamusb-conf-gui.glade $(DESTDIR)/usr/share/pamusb-tools-tcos/

	cd po && make install DESTDIR=$(DESTDIR)
