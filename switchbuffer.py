__author__ = 'denislavrov'
from action.jitrswitch.switch import SwitchLogic
import queue


class SwitchBuffer(SwitchLogic):

	def __init__(self, switch, blocking=True):
		super().__init__(switch)
		self.pqueue = queue.Queue()
		self.blocking = blocking

	def process_packet(self, packet):
		self.pqueue.put(packet)
		if self.blocking:
			packet.drop()

	def discard(self):
		with self.pqueue.mutex:
			self.pqueue.queue.clear()

	def flush(self):
		with self.pqueue.mutex:
			try:
				while True:
					self.inject_after(self.pqueue.get())
			except queue.Empty:
				pass