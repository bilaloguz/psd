import libpsd, logging, threading
from threading import current_thread

class newWatchThread(threading.Thread):
	def __init__(self, target, name, *args):
		self._target = target
		self._name = name
		self._args = args
		threading.Thread.__init__(self)
	
	def run(self):
		self._target(*self._args)

def main():
	logging.basicConfig(filename=libpsd.getGeneralSettings()["logfilepath"], level=libpsd.getGeneralSettings()["loglevel"], format="%(asctime)s %(threadName)s %(message)s")
	logging.info('PSD started @main().')

	for watchName in libpsd.getWatchNames():
		t = newWatchThread(libpsd.startWatch, watchName, watchName)
		t.daemon = True
		t.start()
		logging.info(watchName + " started @main().")
	
if __name__ == '__main__':
	main()