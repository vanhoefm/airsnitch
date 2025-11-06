import abc

# ----------------------------------- Trigger -----------------------------------------

class Trigger():
	"""Define supported Triggers."""

	# Supported Triggers.
	NoTrigger, AfterAuth, Received, Associated, Connected, Disconnected = range(6)
	
	def __str__(self, trigger):
		return ["NoTrigger", "AfterAuth", "Received", \
			"Associated", "Connected", "Disconnected"][trigger]


# ----------------------------------- Action ------------------------------------------

class Action():
	"""Define supported Actions."""

	# Supported Actions.
	NoAction, GetIp, Reconnect, Inject, Function, Receive, Terminate = range(7)

	def __init__(self, trigger, action):
		self.trigger = trigger
		self.action = action
		self.optimized = None
		self.function = None
		self.frame = self.encrypt = None
		self.eth = self.mon = None
		self.delay = None
		self.terminate = self.terminate_delay = False
	
	def set_optimized(self, optimized):
		assert(self.action == self.Reconnect)
		self.optimized = optimized
		
	def set_frame(self, frame, encrypt=False, eth=False, mon=False):
		assert(self.action == self.Inject)
		self.frame = frame
		self.encrypt = encrypt
		self.eth = eth
		self.mon = mon
	
	def set_function(self, function):
		assert(self.action == self.Function)
		self.function = function
		
	def set_receive(self, function, eth=False, mon=False):
		assert(self.action == self.Receive)
		self.function = function
		self.eth = eth
		self.mon = mon
		
	def set_delay(self, delay):
		self.delay = delay
		
	def set_terminate(self, delay=0):
		self.terminate = True
		self.terminate_delay = delay


# ----------------------------------- Test --------------------------------------------

class Test(metaclass=abc.ABCMeta):
	"""Define high-level test case functionality."""

	# Supported Stations.
	Authenticator, Supplicant = range(2)

	def __init__(self, actions=[]):
		self.actions = actions
		self.generated = False

	@abc.abstractmethod
	def generate(self, station):
		pass
		
	def is_action_triggered(self, trigger):
		if len(self.actions) == 0:
			return False
		if self.actions[0].trigger == Trigger.NoTrigger:
			return True
		return self.actions[0].trigger == trigger
				
	def get_next_action(self):
		if len(self.actions) == 0:
			return None
		action = self.actions[0]
		del self.actions[0]
		return action
		
