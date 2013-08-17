
class GamePlayer(object):
	"""Represents/contains the logic for an individual player in a game
	
	Intended to be subclassed for a particular game type
	Override the following methods in a subclass:
	  evaluate()
	  minimax_move()
	  alpha_beta_move()
	  tournament_move()"""
	  
	def __init__(self,player_id):
		""""player_id" is a game-specific identifier for which logical
		player this object is supposed to be representing (i.e., X
		or O for tic-tac-toe, player 1, 2, 3, etc.
		"""
		self.player_id = player_id
		return
	
	def evaluate(self, state):
		"""Override in subclass!
		
		Gives an evaluation value for a game state.
		
		"state" is an object whose type is a game-specific subclass of GameState"""
		pass
	
	def minimax_move(self, state, visited):
		"""Override in subclass!
		
		Returns a move object of a game-type-specific GameMove subclass
		representing the move the player will make from the indicated
		state.
		
		"state" is an object whose type is a game-specific subclass of GameState.
		"visited" is a set of states' repeated representations, giving the states
		 the controller is tracking as visited so far in the game."""
		pass
	
	def alpha_beta_move(self, state, visited):
		"""Override in subclass!
		
		Does the same thing as minimax_move() but with alpha-beta pruning."""
		pass
		
	def tournament_move(self, state, visited):
		"""Override in subclass!
		
		Calls minimax_move() or alpha_beta_move().  Or, performs special behavior 
		if you like."""
		pass
