import copy
import os
import sys
import traceback

# The game function to be used - minimax, alpha-beta, or tournament?
MINIMAX = 0
ALPHA_BETA = 1
TOURN = 2


class PlayerInfo:
	"""Keeps track of information about a game player"""
	def __init__(self,player,name,playerFn):
		"""
		"player" is a subclass of GamePlayer
		
		"name" is a string identifier for the player (the default game framework value is the module name)
		
		"playerFn" indicates
		"""
		self.player = player
		self.name = name
		self.playerFn = playerFn

	def get_name(self):
		return self.name

	def get_player_id(self):
		return self.player.player_id

	def move(self,state,visited):
		if self.playerFn == MINIMAX:
			return self.player.minimax_move(state,visited)
		elif self.playerFn == ALPHA_BETA:
			return self.player.alpha_beta_move(state,visited)
		elif self.playerFn == TOURN:
			return self.player.tournament_move(state,visited)
		else:
			raise ValueException("playerFn is not one of MINIMAX, ALPHA_BETA, or TOURN")

class PlayerException(Exception):
	"""An exception which is raised if the player objects provided to the 
	GameController constructor don't line up with the GameState subclass's
	player IDs."""
	def __init__(self, player):
		""" "player" is a representation of the missing player"""
		self.player = player
	def __str__(self):
		return "Player not found %s" % repr(self.player)

class GameExpansionCounter(object):
	"""Allows many state objects to share one counter for their expansions"""
	def __init__(self, count=0):
		self.count = count

class GameController(object):
	"""The central controller for a game of (whatever)."""
	
	def __init__(self, state, players, max_expansions, wd):
		"""does initial setup of a game
		
		"state" is an object whose type is a game-specific subclass of GameState
		"players" is a list of PlayerInfo objects.

		"maxExpansions" is the maximum number of expansions each player is allowed
		  per turn.
		"wd" is the working directory that should be restored after each player
		  takes a turn.  (In case some player changes the wd and doesn't restore)
		
		Raises PlayerException if there's a mismatch between players and gameIDs"""
		# Reference and ready the game state
		self.state = state
		self.state.clear()
		
		# If game cycles, need state repetition detection
		self.visitedStates = set()
		
		# Maps players' game IDs to player objects
		self.players = {}
		
		# Grab the ID of the next player
		self.nextPlayer = state.get_next_player()
		
		# Make a note of number of remaining expansions
		self.max_expansions = max_expansions
		# self.expansions = self.max_expansions
		self.expansionCounter = GameExpansionCounter(self.max_expansions)
		self.state.set_counter(self.expansionCounter)
		
		# Note the wd in case players open files
		self.wd = wd
		
		# Insert players into map
		self.setup_players(players)
	
	def is_repeat(self, state):
		"""only called by self and self.state
		
		"state" is a game-specific subclass of GameState
		
		Returns True if game cycles and state has been visited before
		Returns False else"""
		if not self.state.repeats():
			return False
		return state.repeated_rep() in self.visitedStates
	
	def clear_repeat(self):			
		"""only called by self and self.state.
		
		If game cycles, clears our repeated-state history."""
		self.visitedStates.clear()
	
	def setup_players(self, players):
		"""Sets up player objects corresponding to game IDs
		
		"players" is a list of PlayerInfo
		
		Raises PlayerException if there's a mismatch between players and gameIDs
	       	"""
		self.players.clear()
		ids = set([p.get_player_id() for p in players])
		for p in self.state.get_players():
			if p not in ids:
				raise PlayerException(p)
		for p in players:
			self.players[p.get_player_id()] = p
	
	def reset(self):
		"""Reset the game"""
		self.clear_repeat()
		self.state.clear()
		self.nextPlayer = self.state.get_next_player()
	
	def game_move(self):
		"""Make one move (one ply) within the game.
		Returns a tuple (move, winner).
		move is an object whose type is a subclass of GameMove,
		winner is the game ID of the winning player
		
		if move is None, there was no move made.
		if winner is None, nobody has won yet.
		if both are None, the game is over and is a draw."""
		# make a note of the player who isn't playing
		for x in self.players.keys():
			if x != self.nextPlayer:
				otherPlayer = x
				break
		
		
		# If there are no remaining moves for this player, either the other
		# player has won or it's a draw
		# self.expansions = 1
		self.expansionCounter.count = 1
		if len(self.state.successors()) == 0:
			if self.state.is_win(otherPlayer):
				return (None, otherPlayer)
			else:
				# None, None for a draw
				return (None, None)
			
		# allow the player max_expansions for this turn
		# self.expansions = self.max_expansions
		self.expansionCounter.count = self.max_expansions
		
		nextPlayer = self.players[self.nextPlayer]
		lastPlayer = None
		
		# player may throw an exception
		try:
			# get player's move, make sure we don't modify the current state
			move = nextPlayer.move(self.state.get_player_state(self.nextPlayer), 
					       self.visitedStates)
			# player may give up
			if move.is_forfeit():
				print "Player", self.nextPlayer, "forfeits."
				return (None, otherPlayer)
			# player may return illegal move
			if not self.state.is_valid_move(move):
				print "Illegal move returned by player", self.nextPlayer, \
						"(", self.players[self.nextPlayer].get_name(), ")"
				return (move, otherPlayer)
			# this player is now last player
			lastPlayer = self.nextPlayer
			# get the new next player and make the indicated move
			self.nextPlayer, clear = self.state.move(move, True)
			if clear:
				self.clear_repeat()
		except:
			print "Exception thrown by player", self.nextPlayer, \
						"(", self.players[self.nextPlayer].get_name(), ")"
			print
			traceback.print_exc()
			print
			return (None, otherPlayer)
		
		os.chdir(self.wd)
		
		# may be a repeated state IF the game cycles
		if self.is_repeat(self.state):
			self.state.handle_cycle()
		# otherwise, if the game cycles, note that we've been here
		elif self.state.repeats():
			self.visitedStates.add(self.state.repeated_rep())
			
		# player may have sacrificed the game
		if self.state.is_win(otherPlayer):
			return (move, otherPlayer)
		
		# player may have won
		if self.state.is_win(lastPlayer):
			return (move, lastPlayer)
		
		# nobody's won or lost yet
		return (move, None)
	
	def play_game(self, quiet=False):
		"""Plays a complete game and returns winner's game ID, or None if a draw"""
		# Just loop until everything's done
		winner = None
		while(winner == None):
			if not quiet:
				print self.state
			move, winner = self.game_move()
			if move == None and winner == None:
				return None
			if move != None and not quiet:
				print "%s:" % self.players[move.get_player()].get_name(), \
									move
				print 
		if not quiet:
			print self.state
		return winner
		
