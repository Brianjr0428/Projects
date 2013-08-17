import collections
import sys
import math

from game_player import *
from gobblet import *




class GobbletPlayer(GamePlayer):
	def __init__(self, playerID):
		GamePlayer.__init__(self, playerID)
		
	# EXAMPLE: Loads a file from the same directory this module is stored in
	#  and returns its contents.  Pattern any file operations you do in your
	#  player on this model.
	#
	# NB: Make a note of the working directory before you cd to the module
	#  directory, and restore it afterward!  The rest of the program may break
	#  otherwise.
	def load_file(self, fname):
		wd = os.getcwd()
		os.chdir("players/gobblet")
		fin = open(fname)
		contents = fin.read()
		fin.close()
		os.chdir(wd)
		return contents
	
        def move_cover_piece(self, state, player, size, x, y):
                #check the availability of given size piece on the board
                for i in range(3):
                        for j in range(3):
                                if state.board_value((x,y)) != None:
                                        if state.board_value((x,y)).size == size:
                                                move = GobbletMove(GobbletMoveDetail((i,j), (x,y), player))
                                                if self.is_valid_move(move):
                                                        return True
                return False

        def move_available_large(self,state, player, x, y):
                #check if large size is available for move
                #check if there is available large piece in hand
                #check if there is available large piece which is on the board
                if state.pieces_available(player, 2) == 0\
                        and self.move_cover_piece(state, player, 2, x, y) == False:
                                return False
                return True

        def move_available_medium(self,state, player, x, y):
                #check if large of medium size is available for move
                #check if there is available large or medium piece in hand
                #check if there is available large or medium piece which is on the board
                if state.pieces_available(player, 1) == 0\
                        and state.pieces_available(player, 2) == 0\
                        and self.move_cover_piece(state, player, 1, x, y) == False\
                        and self.move_cover_piece(state, player, 2, x, y) == False:
                                return False
                return True
                
        def move_available_all(self,state, player, x, y):
                #check if any size is available for move
                #check if there is any available piece in hand
                #check if there is any available piece which is on the board
                if state.pieces_available(player, 0) == 0\
                        and state.pieces_available(player, 1) == 0\
                        and state.pieces_available(player, 2) == 0\
                        and self.move_cover_piece(state, player, 0, x, y) == False\
                        and self.move_cover_piece(state, player, 1, x, y) == False\
                        and self.move_cover_piece(state, player, 2, x, y) == False:
                                return False
                return True

        def available_square(self,x, y, state, currentPlayer, otherPlayer):
                if state.board_value((x,y)) != None:
                        #chack if the square is the large piece of opponent
                        if state.board_value((x,y)).player == otherPlayer\
                                and state.board_value((x,y)).size == 2:
                                        return False
                                        
                        #check if the square is the medium piece of opponent and if it's available to cover 
                        elif state.board_value((x,y)).player == otherPlayer\
                                and state.board_value((x,y)).size == 1\
                                and (not self.move_available_large(state, currentPlayer, x, y)):
                                        return False
                                        
                        #check if the square is the small piece of opponent and if it's available to cover 
                        elif state.board_value((x,y)).player  == otherPlayer\
                                and state.board_value((x,y)).size == 0\
                                and (not self.move_available_medium(state, currentPlayer, x, y)):
                                        return False

                #check if the square is empty but no move available 
                else:
                        if not self.move_available_all(state, currentPlayer, x, y):
                                return False
                return True
        
	def open3(self, state, otherPlayer, currentPlayer):
		s = 0
		
		if self.available_square(0, 0, state, currentPlayer, otherPlayer) \
				and self.available_square(1, 1, state, currentPlayer, otherPlayer)\
				and self.available_square(2, 2, state, currentPlayer, otherPlayer):
			s += 1
		if self.available_square(2, 0, state, currentPlayer, otherPlayer)\
				and self.available_square(1, 1, state, currentPlayer, otherPlayer)\
				and self.available_square(0, 2, state, currentPlayer, otherPlayer):
			s += 1
		for i in range(3):
			if self.available_square(i, 0, state, currentPlayer, otherPlayer)\
                           and self.available_square(i, 1, state, currentPlayer, otherPlayer)\
                           and self.available_square(i, 2, state, currentPlayer, otherPlayer):
                                s += 1
                        if self.available_square(0, i, state, currentPlayer, otherPlayer)\
                           and self.available_square(1, i, state, currentPlayer, otherPlayer)\
                           and self.available_square(2, i, state, currentPlayer, otherPlayer):
                                s += 1

		return s
	
	
	def evaluate(self, state):
		players = state.get_players()
		f = self.open3(state, players[1], players[0]) - self.open3(state, players[0], players[1])
		return f
	

	
	# Does most of the terminal checks for a single step in the search

	# h is steps to the ply horizon
	# players is the list of valid player IDs
	#
	# Returns None if no termination
	# (value, move) otherwise
	def terminal_checks(self, state, h, players):
		# If first player wins, that's a positive
		if state.is_win(players[0]):
			return (sys.maxint, None)
		# If second player wins, that's a negative
		elif state.is_win(players[1]):
			return (-sys.maxint-1, None)
		
		# If there are no more expansions allowed, or if
		# we hit the horizon, evaluate
		if state.expansions_count() <= 0 or h <= 0:
			return (self.evaluate(state), None)
		
		# if no termination, return None
		return None
		
	
	# A helper function for minimax_move().  This one returns a
	# (value, move) tuple that lets us back values up the tree and still
	# return a move at the top.

	# h is an integer representing the distance to the ply horizon
	def minimax_search(self, state, h):
		# Get player IDs
		players = state.get_players()
		
		# Do most of our terminal checks
		term = self.terminal_checks(state, h, players)
		if term != None:
			return term
		
		# Get successor states
		# We should check to see if this is None, but since we just
		#  checked to see if expansion_count was <= 0, we're safe
		successors = state.successors()
		# If there are no successors and nobody's won, it's a draw
		if len(successors) == 0:
			return (0, None)
		
		# Recur on each of the successor states (note we take the state out
		# of the successor tuple with x[1] and decrease the horizon)
		values = [self.minimax_search(s.state, h-1) for s in successors]
		# We're not interested in the moves made, just the minimax values
		values = [x[0] for x in values]
		# Look for the best among the returned values
		# Max if we're player 1
		# Min if we're player 2
		if state.get_next_player() == players[0]:
			max_idx = max(enumerate(values), key=lambda x: x[1])[0]
		else:
			max_idx = min(enumerate(values), key=lambda x: x[1])[0]
		# Return the minimax value and corresponding move
		return (values[max_idx], successors[max_idx].move)

	
	# Get a move for the indicated state, using a minimax search.

	def minimax_move(self, state, visited):

		players = state.get_players()
		currentPlayer = state.get_next_player()
                otherPlayer = players[0]
		if currentPlayer == players[0]:
                        otherPlayer = players[1]
		else :
                        otherPlayer = players[0]
                        
                exp = state.expansions_count()
		successors = len(state.successors())
		print 'successors',successors
		print "expansions_count", exp
		h = int(math.floor(float(exp) ** (1.0 / 8.0)))
		print "Player",state.get_next_player(),"search depth",h
		return self.minimax_search(state,h)[1]

	

	def alpha_beta_search(self, state, h, a, b):
		# Get player IDs
		players = state.get_players()
		player = state.get_next_player()
		
		# Do most of our terminal checks
		term = self.terminal_checks(state, h, players)
		if term != None:
			return term
		
		# Get successor states
		# We should check to see if this is None, but since we just
		#  checked to see if expansion_count was <= 0, we're safe
		successors = state.successors()
		# If there are no successors and nobody's won, it's a draw
		if len(successors) == 0:
			return (0, None)
		
		# We start out with a low best-value and no move
		v = -sys.maxint-1 if player == players[0] else sys.maxint
		m = None
		for s in successors:
			# Recur on the successor state
			s_val = self.alpha_beta_search(s.state, h-1, a, b)
			# If our new value is better than our best value, update the best
			#  value and the best move
			if (player == players[0] and s_val[0] > v) \
					or (player == players[1] and s_val[0] < v):
				v = s_val[0]
				m = s.move
			# If we're maxing and exceeding the min above, just return
			# Likewise if we're minning and exceeding the max above
			if (player == players[0] and v >= b) \
					or (player == players[1] and v <= a):
				return (v, m)
			# Update a,b for the next successor
			a = a if player == players[1] else max(a,v)
			b = b if player == players[0] else min(b,v)
		# return the best value, move we found
		return (v,m)
	

	def alpha_beta_move(self, state, visited):

		players = state.get_players()
		currentPlayer = state.get_next_player()
                otherPlayer = players[0]
		if currentPlayer == players[0]:
                        otherPlayer = players[1]
		else :
                        otherPlayer = players[0]
                        
		successors = len(state.successors())
		print 'successors',successors
		exp = state.expansions_count()
		print "expansions_count", exp
		h = int(math.floor(float(exp) ** (1.0 / 4.0)))
		print "Player",state.get_next_player(),"search depth",h
		return self.alpha_beta_search(state, h, -sys.maxint-1, sys.maxint)[1]
	
	# Just call alpha-beta  
	def tournament_move(self, state, visited):
		return self.alpha_beta_move(state, visited)
		
		
def make_player(playerID):
	return GobbletPlayer(playerID)
