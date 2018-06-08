import libpsd, logging, threading

for watchName in libpsd.getWatchNames():
	t = threading.Thread(target=libpsd.startWatch, args=(watchName,))
	t.start()
	t.join()