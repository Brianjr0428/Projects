from game_player import *
from tictactoe import *


# A ludicrously stupid TicTacToePlayer agent.
class TicTacToePlayer(GamePlayer):

	# Make a note of our player ID
	# see comments on GamePlayer for more details
	def __init__(self, playerID):
		GamePlayer.__init__(self, playerID)
	
	# This agent doesn't evaluate states, so just return 0
	#
	# "state" is a TicTacToeState object
	def evaluate(self, state):
		return 0
	
	# Don't perform any game-tree expansions, just pick the first move
	# that's available in the list of successors.
	#
	# "state" is still a TicTacToeState object
	def minimax_move(self, state, visited):
		# "successors" is a list of (player, state, move) tuples
		successors = state.successors()
		# Take the first successor object's move
		return successors[0].move
	
	# Just call minimax
	def alpha_beta_move(self, state, visited):
		return self.minimax_move(state, visited)
	
	# Just call minimax
	def tournament_move(self, state, visited):
		return self.minimax_move(state, visited)


def make_player(playerID):
	return TicTacToePlayer(playerID)
